using System;
using System.Collections.Generic;
using BrightstarDB.EntityFramework;

namespace Brightstar.Membership.Model
{
    [Entity("http://brightstardb.com/membership-provider/types/login")]
    public interface ILogin
    {
        [Identifier("http://brightstardb.com/membership-provider/logins/")]
        string Id { get; }

        [PropertyType("bsm:applicationName")]
        string ApplicationName { get; set; }

        [PropertyType("bsm:userName")]
        string Username { get; set; }

        [PropertyType("bsm:password")]
        byte[] Password { get; set; }

        [PropertyType("bsm:salt")]
        byte[] PasswordSalt { get; set; }

        [PropertyType("bsm:passwordIterations")]
        int PasswordIterations { get; set; }

        [PropertyType("bsm:passwordQuestion")]
        string PasswordQuestion { get; set; }

        [PropertyType("bsm:passwordAnswer")]
        byte[] PasswordAnswer { get; set; }

        [PropertyType("bsm:passwordAnswerSalt")]
        byte[] PasswordAnswerSalt { get; set; }

        [PropertyType("bsm:passwordAnswerIterations")]
        int PasswordAnswerIterations { get; set; }

        [PropertyType("bsm:email")]
        string Email { get; set; }

        [PropertyType("bsm:comments")]
        string Comments { get; set; }

        [PropertyType("bsm:created")]
        DateTime CreatedDate { get; set; }

        [PropertyType("bsm:lastActive")]
        DateTime LastActive { get; set; }

        [PropertyType("bsm:lastLogin")]
        DateTime LastLoginDate { get; set; }

        [PropertyType("bsm:activated")]
        bool IsActivated { get; set; }

        [PropertyType("bsm:lockedOut")]
        bool IsLockedOut { get; set; }

        [PropertyType("bsm:lastLockedOut")]
        DateTime LastLockedOutDate { get; set; }

        [PropertyType("bsm:lastLockedOutReason")]
        string LastLockedOutReason { get; set; }

        [PropertyType("bsm:loginAttempts")]
        int? LoginAttempts { get; set; }

        [PropertyType("bsm:roles")]
        ICollection<string> Roles { get; set; }
    }
}
