import pytest
from pathlib import Path
from pulse.ecosystems.maven.plugin import MavenPlugin
from pulse.ecosystems.base import ScanContext, ScannerConfig
import logging

def test_maven_detection(tmp_path):
    plugin = MavenPlugin()
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    assert not plugin.detect(context)

    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    assert plugin.detect(context)

def test_maven_pom_parsing(tmp_path):
    plugin = MavenPlugin()
    
    pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.mycompany.app</groupId>
    <artifactId>my-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <jackson.version>2.15.2</jackson.version>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.slf4j</groupId>
                <artifactId>slf4j-api</artifactId>
                <version>2.0.7</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
    (tmp_path / "pom.xml").write_text(pom_content, encoding="utf-8")
    
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    raw_deps = plugin.parse(context)
    
    names = [d.name for d in raw_deps]
    versions = {d.name: d.version_spec for d in raw_deps}
    scopes = {d.name: d.metadata.get("scope") for d in raw_deps}
    
    assert "com.fasterxml.jackson.core:jackson-databind" in names
    assert versions["com.fasterxml.jackson.core:jackson-databind"] == "2.15.2"
    assert scopes["com.fasterxml.jackson.core:jackson-databind"] == "compile"
    
    assert "org.slf4j:slf4j-api" in names
    assert versions["org.slf4j:slf4j-api"] == "2.0.7" # resolved from dependencyManagement
    
    assert "junit:junit" in names
    assert versions["junit:junit"] == "4.13.2"
    assert scopes["junit:junit"] == "test"
