import pytest
from pulse.remediation.command_generator import generate_upgrade_command


def test_python_command_generation():
    cmd = generate_upgrade_command("Django", "python", "4.2.26")
    assert cmd == "pip install Django==4.2.26"


def test_npm_command_generation():
    cmd = generate_upgrade_command("react", "npm", "18.3.1")
    assert cmd == "npm install react@18.3.1"


def test_pnpm_command_generation():
    cmd = generate_upgrade_command("react", "node", "18.3.1", package_manager="pnpm")
    assert cmd == "pnpm add react@18.3.1"


def test_yarn_command_generation():
    cmd = generate_upgrade_command("react", "node", "18.3.1", package_manager="yarn")
    assert cmd == "yarn add react@18.3.1"


def test_composer_command_generation():
    cmd = generate_upgrade_command("laravel/framework", "composer", "11.0.0")
    assert cmd == "composer require laravel/framework:11.0.0"


def test_cargo_command_generation():
    cmd = generate_upgrade_command("serde", "cargo", "1.0.218")
    assert cmd == "cargo add serde@1.0.218"


def test_go_command_generation():
    cmd = generate_upgrade_command("github.com/gin-gonic/gin", "go", "1.10.0")
    assert cmd == "go get github.com/gin-gonic/gin@v1.10.0"


def test_ruby_command_generation():
    cmd = generate_upgrade_command("rails", "ruby", "7.1.0")
    assert cmd == "bundle update rails"


def test_nuget_command_generation():
    cmd = generate_upgrade_command("Newtonsoft.Json", "nuget", "13.0.3")
    assert cmd == "dotnet add package Newtonsoft.Json --version 13.0.3"


def test_maven_command_generation():
    cmd = generate_upgrade_command("org.springframework:spring-core", "maven", "6.1.5")
    assert cmd == "mvn versions:use-latest-releases"
