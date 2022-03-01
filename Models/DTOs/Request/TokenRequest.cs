using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CoreJWTApi2.Models.DTOs.Request
{
    public class TokenRequest
    {
        [Required]
        public string Token { get; set; }//current jwt token client has

        [Required]
        public string RefreshToken { get; set; }
    }
}
