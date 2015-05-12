using BrightstarDB.EntityFramework;

namespace Brightstar.Membership.Model
{
    [Entity("bsm:role")]
    public interface IRole
    {
        [Identifier("http://brightstardb.com/membership-provider/roles/")]
        string Id { get; }
    }
}