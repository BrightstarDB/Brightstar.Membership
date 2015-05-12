using BrightstarDB.EntityFramework;

namespace Brightstar.Membership.Model
{
    /// <summary>
    /// Provides a typed stub that logins can be converted to when they are deleted without deleting the underlying data.
    /// The data can be accessed either by direct SPARQL queries or by casting the entity back to an ILogin instance.
    /// </summary>
    [Entity("http://brightstardb.com/membership-provider/types/login")]
    public interface IDeletedLogin
    {
        [Identifier("http://brightstardb.com/membership-provider/logins/")]
        string Id { get; }
    }
}