using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using demo_oidc_web_client.Models;
using System.Net.Http;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;

namespace demo_oidc_web_client.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IDiscoveryCache _discoveryCache;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IDiscoveryCache discoveryCache)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _discoveryCache = discoveryCache;
        }

        public IActionResult Index()
        {
            return View();
        }
        [Authorize]
        public IActionResult Secure()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult Logout()
        {
            return new SignOutResult(new[] { "Cookies", "oidc" });
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
