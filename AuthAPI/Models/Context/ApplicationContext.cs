using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Models.Context
{
    public class ApplicationContext : DbContext
    {
        public ApplicationContext()
        { }       

        public ApplicationContext(DbContextOptions<ApplicationContext> options) : base(options)
        { }

        public DbSet<User> Users { get; set; }
    }
}