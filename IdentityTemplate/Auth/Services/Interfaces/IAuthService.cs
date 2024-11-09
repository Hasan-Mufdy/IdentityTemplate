using IdentityTemplate.Auth.Dtos;
using IdentityTemplate.Auth.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityTemplate.Auth.Services.Interfaces
{
    public interface IAuthService
    {
        Task<LoginDto> Login(LoginModel model);
        Task<RegisterAdminDto> RegisterAdmin(RegisterModel model);
        Task<RegisterDto> Register(RegisterModel model);
    }
}
