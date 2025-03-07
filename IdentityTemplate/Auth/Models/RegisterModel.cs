﻿using System.ComponentModel.DataAnnotations;

namespace IdentityTemplate.Auth.Models
{
    public class RegisterModel
    {
        [Required]
        public string Username { get; set; }

        [EmailAddress]
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
