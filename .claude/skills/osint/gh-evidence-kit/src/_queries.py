"""
Query models for evidence lookups.

These Pydantic models validate input parameters before making API calls.
They enforce GitHub naming conventions and required fields.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


class RepositoryQuery(BaseModel):
    """Repository identifier with validation."""

    owner: str = Field(..., min_length=1, max_length=39)
    name: str = Field(..., min_length=1, max_length=100)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @field_validator("owner", "name")
    @classmethod
    def validate_github_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$", v):
            if len(v) == 1 and v.isalnum():
                return v
            raise ValueError(f"Invalid GitHub name format: {v}")
        return v


class CommitQuery(BaseModel):
    """Query for a commit observation."""

    repo: RepositoryQuery
    sha: Annotated[str, Field(min_length=7, max_length=40)]

    @field_validator("sha")
    @classmethod
    def validate_sha(cls, v: str) -> str:
        if not re.match(r"^[a-f0-9]+$", v.lower()):
            raise ValueError(f"Invalid commit SHA: {v}")
        return v.lower()


class IssueQuery(BaseModel):
    """Query for an issue/PR observation."""

    repo: RepositoryQuery
    number: int = Field(..., gt=0)
    is_pull_request: bool = False


class FileQuery(BaseModel):
    """Query for a file observation."""

    repo: RepositoryQuery
    path: str = Field(..., min_length=1)
    ref: str = "HEAD"


class BranchQuery(BaseModel):
    """Query for a branch observation."""

    repo: RepositoryQuery
    branch_name: str = Field(..., min_length=1)


class TagQuery(BaseModel):
    """Query for a tag observation."""

    repo: RepositoryQuery
    tag_name: str = Field(..., min_length=1)


class ReleaseQuery(BaseModel):
    """Query for a release observation."""

    repo: RepositoryQuery
    tag_name: str = Field(..., min_length=1)


class ForkQuery(BaseModel):
    """Query for fork relationships."""

    repo: RepositoryQuery


class WaybackQuery(BaseModel):
    """Query for Wayback Machine snapshots."""

    url: HttpUrl
    from_date: str | None = None
    to_date: str | None = None

    @field_validator("from_date", "to_date")
    @classmethod
    def validate_date(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.match(r"^\d{4,14}$", v):
            raise ValueError("Date must be YYYY, YYYYMM, YYYYMMDD, or YYYYMMDDHHMMSS")
        return v


class GHArchiveQuery(BaseModel):
    """Query for GH Archive events."""

    repo: RepositoryQuery | None = None
    actor: str | None = None
    event_type: str | None = None
    from_date: str = Field(..., pattern=r"^\d{12}$")  # YYYYMMDDHHMM
    to_date: str | None = None

    @model_validator(mode="after")
    def validate_at_least_one_filter(self) -> "GHArchiveQuery":
        if not self.repo and not self.actor:
            raise ValueError("Must specify at least repo or actor")
        return self
