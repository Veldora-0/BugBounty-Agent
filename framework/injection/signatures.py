"""
Structured Database & Template Error Signatures for BugBounty-Agent (Phase 10).

Maintains structured detection patterns for SQL syntax errors, database drivers,
NoSQL exceptions, and template engine syntax faults.
An error signature provides contextual evidence, never automatic proof of exploitability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from framework.injection.model import InjectionConfidence


class ErrorSignature:
    """A structured signature for database or interpreter error detection."""

    def __init__(
        self,
        signature_id: str,
        family: str,
        driver: str,
        pattern: str,
        confidence: InjectionConfidence = InjectionConfidence.OBSERVED,
        description: str = "",
    ):
        self.signature_id = signature_id
        self.family = family
        self.driver = driver
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.confidence = confidence
        self.description = description

    def match(self, text: str) -> Optional[Dict[str, Any]]:
        """Checks if text contains this signature and returns evidence snippet."""
        if not text:
            return None
        m = self.regex.search(text)
        if m:
            # Capture bounded context around match
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].strip()
            return {
                "signature_id": self.signature_id,
                "family": self.family,
                "driver": self.driver,
                "confidence": self.confidence.value,
                "matched_text": m.group(0),
                "context_snippet": snippet,
                "description": self.description,
            }
        return None


# Catalog of structured signatures
SIGNATURE_CATALOG: List[ErrorSignature] = [
    # MySQL / MariaDB
    ErrorSignature(
        "SIG-SQL-MYSQL-01",
        "MySQL",
        "mysql/pdo/mysqli",
        r"you have an error in your sql syntax(?:;| near)",
        description="MySQL syntax error near token",
    ),
    ErrorSignature(
        "SIG-SQL-MYSQL-02",
        "MySQL",
        "php-mysql",
        r"Warning:\s*mysql_[a-zA-Z_]+\(\)",
        description="PHP MySQL driver warning",
    ),
    ErrorSignature(
        "SIG-SQL-MYSQL-03",
        "MySQL",
        "mysql-client",
        r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
        description="MySQL/MariaDB version manual guidance",
    ),

    # PostgreSQL
    ErrorSignature(
        "SIG-SQL-PGSQL-01",
        "PostgreSQL",
        "pg/libpq",
        r"ERROR:\s*syntax error at or near\s*",
        description="PostgreSQL syntax error",
    ),
    ErrorSignature(
        "SIG-SQL-PGSQL-02",
        "PostgreSQL",
        "jdbc-postgres",
        r"org\.postgresql\.util\.PSQLException",
        description="PostgreSQL JDBC driver exception",
    ),
    ErrorSignature(
        "SIG-SQL-PGSQL-03",
        "PostgreSQL",
        "php-pg",
        r"Warning:\s*pg_[a-zA-Z_]+\(\)",
        description="PHP PostgreSQL driver warning",
    ),

    # SQLite
    ErrorSignature(
        "SIG-SQL-SQLITE-01",
        "SQLite",
        "sqlite3",
        r"sqlite3\.OperationalError:\s*unrecognized token",
        description="Python SQLite operational error",
    ),
    ErrorSignature(
        "SIG-SQL-SQLITE-02",
        "SQLite",
        "sqlite3",
        r"SQL logic error or missing database|near \".*\": syntax error",
        description="SQLite logic or syntax error",
    ),

    # Microsoft SQL Server
    ErrorSignature(
        "SIG-SQL-MSSQL-01",
        "Microsoft SQL Server",
        "oledb/sqlsrv",
        r"Unclosed quotation mark before the character string",
        description="MSSQL unclosed quotation mark",
    ),
    ErrorSignature(
        "SIG-SQL-MSSQL-02",
        "Microsoft SQL Server",
        "oledb/sqlsrv",
        r"Microsoft OLE DB Provider for SQL Server|Incorrect syntax near",
        description="MSSQL OLE DB provider error",
    ),

    # Oracle
    ErrorSignature(
        "SIG-SQL-ORACLE-01",
        "Oracle",
        "oci8/jdbc-oracle",
        r"ORA-00933:\s*SQL command not properly ended",
        description="Oracle ORA-00933 syntax error",
    ),
    ErrorSignature(
        "SIG-SQL-ORACLE-02",
        "Oracle",
        "oci8/jdbc-oracle",
        r"ORA-00936:\s*missing expression",
        description="Oracle ORA-00936 missing expression",
    ),

    # Generic ORM & DB
    ErrorSignature(
        "SIG-SQL-GENERIC-01",
        "Generic SQL",
        "hibernate",
        r"org\.hibernate\.QueryException|org\.hibernate\.exception\.SQLGrammarException",
        description="Java Hibernate SQL grammar exception",
    ),
    ErrorSignature(
        "SIG-SQL-GENERIC-02",
        "Generic SQL",
        "sequelize",
        r"SequelizeDatabaseError:\s*syntax error",
        description="NodeJS Sequelize database error",
    ),

    # NoSQL (MongoDB)
    ErrorSignature(
        "SIG-NOSQL-MONGO-01",
        "MongoDB",
        "mongodb-driver",
        r"MongoError|MongoServerError:\s*Cannot use '.*' on null",
        description="MongoDB server error",
    ),
    ErrorSignature(
        "SIG-NOSQL-MONGO-02",
        "MongoDB",
        "mongoose",
        r"Cast to ObjectId failed for value|BSONTypeError",
        description="Mongoose/BSON type conversion failure",
    ),

    # Template Engines (SSTI)
    ErrorSignature(
        "SIG-SSTI-JINJA-01",
        "Jinja2",
        "python-jinja2",
        r"jinja2\.exceptions\.TemplateSyntaxError",
        description="Jinja2 template syntax error",
    ),
    ErrorSignature(
        "SIG-SSTI-TWIG-01",
        "Twig",
        "php-twig",
        r"Twig_Error_Syntax|Twig\\Error\\SyntaxError",
        description="Twig template syntax error",
    ),
    ErrorSignature(
        "SIG-SSTI-FREEMARKER-01",
        "FreeMarker",
        "java-freemarker",
        r"freemarker\.core\.ParseException|FreeMarker template error",
        description="FreeMarker template parser error",
    ),
    ErrorSignature(
        "SIG-SSTI-VELOCITY-01",
        "Velocity",
        "java-velocity",
        r"org\.apache\.velocity\.exception\.ParseErrorException",
        description="Apache Velocity parse error exception",
    ),
]


class ErrorSignatureMatcher:
    """Matches text against the structured error signature catalog."""

    @classmethod
    def match(cls, text: str) -> Optional[Dict[str, Any]]:
        """
        Evaluates text across all registered signatures.
        Returns first or best matching signature evidence.
        """
        if not text:
            return None
        for sig in SIGNATURE_CATALOG:
            res = sig.match(text)
            if res:
                return res
        return None

    @classmethod
    def match_all(cls, text: str) -> List[Dict[str, Any]]:
        """Returns all matching signatures in the provided text."""
        matches = []
        if not text:
            return matches
        for sig in SIGNATURE_CATALOG:
            res = sig.match(text)
            if res:
                matches.append(res)
        return matches
