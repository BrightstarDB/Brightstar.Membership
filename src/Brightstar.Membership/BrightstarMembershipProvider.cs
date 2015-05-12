using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Security;
using Brightstar.Membership.Model;

namespace Brightstar.Membership
{
    public class BrightstarMembershipProvider : MembershipProvider
    {
        
        #region Configuration and Initialization

        private string _applicationName;
        private bool _requiresUniqueEmail = true;
        private int _maxInvalidPasswordAttempts;
        private int _passwordAttemptWindow;
        private int _minRequiredPasswordLength;
        private int _minRequiredNonalphanumericCharacters;
        private bool _enablePasswordReset;
        private string _passwordStrengthRegularExpression;
        private string _connectionString;
        private string _name;
        private RandomNumberGenerator _rng;

        private const string DefaultProviderName = "BrightstarMembershipProvider";

        private static string GetConfigValue(string configValue, string defaultValue)
        {
            return string.IsNullOrEmpty(configValue) ? defaultValue : configValue;
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null) throw new ArgumentNullException("config");

            _name = string.IsNullOrEmpty(name) ? DefaultProviderName : name;

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "BrightstarDB Membership Provider");
            }

            base.Initialize(name, config);

            _applicationName = GetConfigValue(config["applicationName"], null);
            if (_applicationName == null)
            {
                throw new ConfigurationErrorsException("The BrightstrMembershipProvider MUST be configured with an applicationName attribute.");
            }
            _maxInvalidPasswordAttempts = Convert.ToInt32(
                          GetConfigValue(config["maxInvalidPasswordAttempts"], "10"));
            _passwordAttemptWindow = Convert.ToInt32(
                          GetConfigValue(config["passwordAttemptWindow"], "10"));
            _minRequiredNonalphanumericCharacters = Convert.ToInt32(
                          GetConfigValue(config["minRequiredNonalphanumericCharacters"], "1"));
            _minRequiredPasswordLength = Convert.ToInt32(
                          GetConfigValue(config["minRequiredPasswordLength"], "6"));
            _enablePasswordReset = Convert.ToBoolean(
                          GetConfigValue(config["enablePasswordReset"], "true"));
            _passwordStrengthRegularExpression = Convert.ToString(
                           GetConfigValue(config["passwordStrengthRegularExpression"], ""));
            _requiresUniqueEmail = Convert.ToBoolean(
                GetConfigValue(config["requiresUniqueEmail"], "true"));
            MinPasswordHashIterations = Convert.ToInt32(
                GetConfigValue(config["minPasswordHashIterations"], "4096"));
            MaxPasswordHashIterations = Convert.ToInt32(
                GetConfigValue(config["maxPasswordHashIterations"], "32768"));

            _connectionString = GetConfigValue(config["connectionString"], BrightstarDB.Configuration.ConnectionString);
            if (string.IsNullOrEmpty(_connectionString))
            {
                throw new ConfigurationErrorsException("The BrightstarDB connection string must be specified either in the provider configuration or in the appSettings.");
            }
            _rng = new RNGCryptoServiceProvider();
        }
        
        #endregion

        #region Properties

        public override string ApplicationName
        {
            get { return _applicationName; }
            set { _applicationName = value; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return _maxInvalidPasswordAttempts; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonalphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return _minRequiredPasswordLength; }
        }

        public override int PasswordAttemptWindow
        {
            get { return _passwordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _passwordStrengthRegularExpression; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return _requiresUniqueEmail; }
        }

        /// <summary>
        /// Indicates whether the membership provider is configured to allow users to retrieve their passwords.
        /// </summary>
        /// <returns>
        /// true if the membership provider is configured to support password retrieval; otherwise, false. The default is false.
        /// </returns>
        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }



        /// <summary>
        /// Get or set the minimum number of password hashing iterations. 
        /// </summary>
        /// <remarks>NOTE: The actual number of iterations used for a given login
        /// password will be a random number between <see cref="MinPasswordHashIterations"/>
        /// and <see cref="MaxPasswordHashIterations"/>.</remarks>
        public int MinPasswordHashIterations { get; set; }

        /// <summary>
        /// Get or set the maximum number of password hashing iterations.
        /// </summary>
        /// <remarks>NOTE: The actual number of iterations used for a given login
        /// password will be a random number between <see cref="MinPasswordHashIterations"/>
        /// and <see cref="MaxPasswordHashIterations"/>.</remarks>
        public int MaxPasswordHashIterations { get; set; }

        #endregion

        #region Private Methods

        private LoginContext GetContext()
        {
            return new LoginContext(_connectionString);
        }

        private byte[] CreateSalt()
        {
            var buffer = new byte[32];
            _rng.GetBytes(buffer);
            return buffer;
        }

        private static byte[] CreatePasswordHash(string password, byte[] salt, int iterationCount)
        {
            var derivedBytes = new Rfc2898DeriveBytes(password, salt, iterationCount);
            return derivedBytes.GetBytes(32);
        }
       
        /// <summary>
        /// This helper method returns a .NET MembershipUser object generated from the supplied BrightstarDB entity
        /// </summary>
        private MembershipUser ConvertLoginToMembershipUser(ILogin login)
        {
            if (login == null) return null;
            var user = new MembershipUser(_name,
                login.Username, login.Id, login.Email,
                login.PasswordQuestion, login.Comments, 
                login.IsActivated, login.IsLockedOut,
                login.CreatedDate, login.LastLoginDate,
                login.LastActive, DateTime.UtcNow, 
                login.LastLockedOutDate);
            return user;
        }

        #endregion

        public override MembershipUser CreateUser(string username, string password, string email,
            string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey,
            out MembershipCreateStatus status)
        {
            var args = new ValidatePasswordEventArgs(email, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (string.IsNullOrEmpty(email))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (string.IsNullOrEmpty(password))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (RequiresUniqueEmail && GetUserNameByEmail(email) != "")
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            var u = GetUser(username, false);
            if (u != null)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }
            try
            {
                var salt = CreateSalt();
                var buff = new byte[4];
                _rng.GetNonZeroBytes(buff);
                var seed = BitConverter.ToInt32(buff, 0);
                var random = new Random(seed);
                var iterations = random.Next(MinPasswordHashIterations, MaxPasswordHashIterations);

                //Create a new Login entity and set the properties
                var login = new Login
                {
                    Username = username,
                    Email = email,
                    PasswordSalt = salt,
                    Password = CreatePasswordHash(password, salt, iterations),
                    PasswordIterations = iterations,
                    CreatedDate = DateTime.UtcNow,
                    IsActivated = true,
                    IsLockedOut = false,
                    LastLockedOutDate = DateTime.UtcNow,
                    LastLoginDate = DateTime.UtcNow,
                    LastActive = DateTime.UtcNow
                };
                
                // If a password question and answer are provided, store the question and a hash of the answer
                if (!string.IsNullOrEmpty(passwordQuestion) && !string.IsNullOrEmpty(passwordAnswer))
                {
                    login.PasswordQuestion = passwordQuestion;
                    login.PasswordAnswer = CreatePasswordHash(passwordAnswer, salt, iterations);
                    login.PasswordAnswerSalt = salt;
                    login.PasswordAnswerIterations = iterations;
                }
                else
                {
                    if (RequiresQuestionAndAnswer)
                    {
                        status = string.IsNullOrEmpty(passwordQuestion)
                            ? MembershipCreateStatus.InvalidQuestion
                            : MembershipCreateStatus.InvalidAnswer;
                        return null;
                    }
                }

                //Create a context using the connection string in the Web.Config
                var context = GetContext();

                //Add the entity to the context
                context.Logins.Add(login);
                
                //Save the changes to the BrightstarDB store
                context.SaveChanges();

                status = MembershipCreateStatus.Success;
                return GetUser(username, true /*online*/);
            }
            catch (Exception)
            {
                status = MembershipCreateStatus.ProviderError;
                return null;
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (string.IsNullOrEmpty(username)) return null;
            //Create a context using the connection string in Web.config
            var context = GetContext();
            //Query the store for a Login that matches the supplied username
            var login = context.Logins.FirstOrDefault(l => l.Username.Equals(username));
            if (login == null) return null;
            if (userIsOnline)
            {
                //if the call states that the user is online, update the LastActive property of the ILogin
                login.LastActive = DateTime.UtcNow;
                context.SaveChanges();
            }
            return ConvertLoginToMembershipUser(login);
        }

        public override string GetUserNameByEmail(string email)
        {
            if (string.IsNullOrEmpty(email)) return "";
            //Create a context using the connection string in Web.config
            var context = GetContext();
            //Query the store for a Login that matches the supplied username
            var login = context.Logins.FirstOrDefault(l => l.Email.Equals(email));
            return login == null ? string.Empty : login.Username;
        }

        public override bool ValidateUser(string username, string password)
        {
            //Create a context using the connection string set in Web.config
            var context = GetContext();
            //Query the store for a Login matching the supplied username
            var login = context.Logins.FirstOrDefault(l => l.Username.Equals(username));
            if (login == null) return false;
            //Check the properties on the Login to ensure the user account is activate and not locked out
            if (login.IsLockedOut || !login.IsActivated) return false;
            //Validate the password of the Login against the supplied password
            var validatePassword = login.Password.SequenceEqual(CreatePasswordHash(password, login.PasswordSalt, login.PasswordIterations));
            return validatePassword;
        }


        #region MembershipProvider properties and methods not implemented for this tutorial
        /// <summary>
        /// Clears a lock so that the membership user can be validated.
        /// </summary>
        /// <returns>
        /// true if the membership user was successfully unlocked; otherwise, false.
        /// </returns>
        /// <param name="userName">The membership user whose lock status you want to clear.</param>
        public override bool UnlockUser(string userName)
        {
            using (var context = GetContext())
            {
                var login = context.Logins.FirstOrDefault(l => l.Username.Equals(userName));
                if (login == null) return false;
                login.IsLockedOut = false;
                context.SaveChanges();
                return true;
            }
        }

        /// <summary>
        /// Removes a user from the membership data source. 
        /// </summary>
        /// <returns>
        /// true if the user was successfully deleted; otherwise, false.
        /// </returns>
        /// <param name="username">The name of the user to delete.</param>
        /// <param name="deleteAllRelatedData">true to delete data related to the user from the database; false to leave data related to the user in the database.</param>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            using (var context = GetContext())
            {
                var login = context.Logins.FirstOrDefault(l => l.Username.Equals(username));
                if (login == null) return false;
                if (deleteAllRelatedData)
                {
                    context.DeleteObject(login);
                }
                else
                {
                    ((Login)login).Become<IDeletedLogin>();
                    ((Login)login).Unbecome<ILogin>();
                }
                context.SaveChanges();
                return true;
            }
        }

        /// <summary>
        /// Gets a collection of all the users in the data source in pages of data.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
        /// </returns>
        /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets the number of users currently accessing the application.
        /// </summary>
        /// <returns>
        /// The number of users currently accessing the application.
        /// </returns>
        public override int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a collection of membership users where the user name contains the specified user name to match.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
        /// </returns>
        /// <param name="usernameToMatch">The user name to search for.</param><param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a collection of membership users where the e-mail address contains the specified e-mail address to match.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
        /// </returns>
        /// <param name="emailToMatch">The e-mail address to search for.</param><param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Indicates whether the membership provider is configured to allow users to reset their passwords.
        /// </summary>
        /// <returns>
        /// true if the membership provider supports password reset; otherwise, false. The default is true.
        /// </returns>
        public override bool EnablePasswordReset
        {
            get { throw new NotImplementedException(); }
        }


        /// <summary>
        /// Processes a request to update the password question and answer for a membership user.
        /// </summary>
        /// <returns>
        /// true if the password question and answer are updated successfully; otherwise, false.
        /// </returns>
        /// <param name="username">The user to change the password question and answer for. </param><param name="password">The password for the specified user. </param><param name="newPasswordQuestion">The new password question for the specified user. </param><param name="newPasswordAnswer">The new password answer for the specified user. </param>
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets the password for the specified user name from the data source.
        /// </summary>
        /// <returns>
        /// The password for the specified user name.
        /// </returns>
        /// <param name="username">The user to retrieve the password for. </param><param name="answer">The password answer for the user. </param>
        public override string GetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Processes a request to update the password for a membership user.
        /// </summary>
        /// <returns>
        /// true if the password was updated successfully; otherwise, false.
        /// </returns>
        /// <param name="username">The user to update the password for. </param><param name="oldPassword">The current password for the specified user. </param><param name="newPassword">The new password for the specified user. </param>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Resets a user's password to a new, automatically generated password.
        /// </summary>
        /// <returns>
        /// The new password for the specified user.
        /// </returns>
        /// <param name="username">The user to reset the password for. </param><param name="answer">The password answer for the specified user. </param>
        public override string ResetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Updates information about a user in the data source.
        /// </summary>
        /// <param name="user">A <see cref="T:System.Web.Security.MembershipUser"/> object that represents the user to update and the updated information for the user. </param>
        public override void UpdateUser(MembershipUser user)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets user information from the data source based on the unique identifier for the membership user. Provides an option to update the last-activity date/time stamp for the user.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the specified user's information from the data source.
        /// </returns>
        /// <param name="providerUserKey">The unique identifier for the membership user to get information for.</param><param name="userIsOnline">true to update the last-activity date/time stamp for the user; false to return user information without updating the last-activity date/time stamp for the user.</param>
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a value indicating whether the membership provider is configured to require the user to answer a password question for password reset and retrieval.
        /// </summary>
        /// <returns>
        /// true if a password answer is required for password reset and retrieval; otherwise, false. The default is true.
        /// </returns>
        public override bool RequiresQuestionAndAnswer
        {
            get { throw new NotImplementedException(); }
        }


        #endregion

        
    }

    public interface IDeletedLogin
    {
    }
}