# Unified Technology Catalog for PULSE CLI website module

TECHNOLOGY_CATALOG = {
    "wordpress": {
        "display_name": "WordPress",
        "aliases": ["wordpress", "wp"],
        "lookup_strategy": "osv",
        "ecosystem": "WordPress",
        "package": "wordpress",
        "supports_versions": True,
        "coverage": "full"
    },
    "drupal": {
        "display_name": "Drupal",
        "aliases": ["drupal"],
        "lookup_strategy": "osv",
        "ecosystem": "Drupal",
        "package": "drupal",
        "supports_versions": True,
        "coverage": "full"
    },
    "joomla": {
        "display_name": "Joomla",
        "aliases": ["joomla"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:joomla:joomla\\!",
        "supports_versions": True,
        "coverage": "full"
    },
    "magento": {
        "display_name": "Magento",
        "aliases": ["magento"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:magentocommerce:magento",
        "supports_versions": True,
        "coverage": "full"
    },
    "next.js": {
        "display_name": "Next.js",
        "aliases": ["next.js", "nextjs"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "next",
        "cpe": "cpe:2.3:a:vercel:next.js",
        "supports_versions": True,
        "coverage": "full"
    },
    "nuxt.js": {
        "display_name": "Nuxt.js",
        "aliases": ["nuxt.js", "nuxt", "nuxtjs"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "nuxt",
        "cpe": "cpe:2.3:a:nuxtjs:nuxt.js",
        "supports_versions": True,
        "coverage": "full"
    },
    "react": {
        "display_name": "React",
        "aliases": ["react", "reactjs", "react.js"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "react",
        "cpe": "cpe:2.3:a:facebook:react",
        "supports_versions": True,
        "coverage": "partial"
    },
    "angular": {
        "display_name": "Angular",
        "aliases": ["angular", "angularjs", "angular.js"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "@angular/core",
        "cpe": "cpe:2.3:a:google:angular",
        "supports_versions": True,
        "coverage": "partial"
    },
    "vue": {
        "display_name": "Vue.js",
        "aliases": ["vue", "vuejs", "vue.js"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "vue",
        "cpe": "cpe:2.3:a:vuejs:vue.js",
        "supports_versions": True,
        "coverage": "partial"
    },
    "jquery": {
        "display_name": "jQuery",
        "aliases": ["jquery"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "jquery",
        "cpe": "cpe:2.3:a:jquery:jquery",
        "supports_versions": True,
        "coverage": "partial"
    },
    "nginx": {
        "display_name": "Nginx",
        "aliases": ["nginx"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:nginx:nginx",
        "supports_versions": True,
        "coverage": "full"
    },
    "apache": {
        "display_name": "Apache HTTP Server",
        "aliases": ["apache", "apache http server", "httpd"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:apache:http_server",
        "supports_versions": True,
        "coverage": "full"
    },
    "iis": {
        "display_name": "IIS",
        "aliases": ["iis", "microsoft-iis"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:microsoft:iis",
        "supports_versions": True,
        "coverage": "full"
    },
    "tomcat": {
        "display_name": "Apache Tomcat",
        "aliases": ["tomcat", "apache tomcat"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:apache:tomcat",
        "supports_versions": True,
        "coverage": "full"
    },
    "php": {
        "display_name": "PHP",
        "aliases": ["php"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:php:php",
        "supports_versions": True,
        "coverage": "full"
    },
    "asp.net": {
        "display_name": "ASP.NET",
        "aliases": ["asp.net", "aspnet", "microsoft asp.net"],
        "lookup_strategy": "nvd",
        "cpe": "cpe:2.3:a:microsoft:asp.net",
        "supports_versions": True,
        "coverage": "full"
    },
    "svelte": {
        "display_name": "Svelte",
        "aliases": ["svelte"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "svelte",
        "cpe": "cpe:2.3:a:svelte:svelte",
        "supports_versions": True,
        "coverage": "partial"
    },
    "vite": {
        "display_name": "Vite",
        "aliases": ["vite"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "vite",
        "cpe": "cpe:2.3:a:vitejs:vite",
        "supports_versions": True,
        "coverage": "partial"
    },
    "bootstrap": {
        "display_name": "Bootstrap",
        "aliases": ["bootstrap", "twitter-bootstrap"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "bootstrap",
        "cpe": "cpe:2.3:a:getbootstrap:bootstrap",
        "supports_versions": True,
        "coverage": "partial"
    },
    "tailwind": {
        "display_name": "Tailwind CSS",
        "aliases": ["tailwind", "tailwindcss"],
        "lookup_strategy": "both",
        "ecosystem": "npm",
        "package": "tailwindcss",
        "cpe": "cpe:2.3:a:tailwindcss:tailwindcss",
        "supports_versions": True,
        "coverage": "partial"
    }
}
