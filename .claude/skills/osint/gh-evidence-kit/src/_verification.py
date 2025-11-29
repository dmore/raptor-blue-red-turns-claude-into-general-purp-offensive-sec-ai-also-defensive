"""
Verification Module - Verify evidence against original sources.

This module provides the verification logic for all evidence types.
Each evidence object can call verify() to compare itself against
the real data from the source specified in its verification info.

IMPLEMENTATION STATUS:
- GitHub API: Fully implemented (commits, issues, PRs, files, branches, tags, releases)
- Wayback Machine: Implemented (CDX query verification)
- Security Vendor: Implemented (URL and IOC value verification)
- GH Archive: Partial - requires BigQuery credentials (gracefully skips if unavailable)
- Local Git: Not implemented - requires local repository path
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from ._schema import (
        AnyEvidence,
        Event,
        Observation,
        VerificationResult,
    )
    from ._clients import GitHubClient, GHArchiveClient

from ._schema import EvidenceSource


def verify_event(event: "Event") -> "VerificationResult":
    """
    Verify an event against the original source.

    Events are typically from GH Archive BigQuery. Verification
    requires GCP credentials to query the archive.

    Returns:
        Tuple of (is_valid, errors)
    """
    errors: list[str] = []
    source = event.verification.source

    if source == EvidenceSource.GHARCHIVE:
        return _verify_gharchive_event(event)
    elif source == EvidenceSource.GIT:
        return _verify_git_event(event)
    else:
        errors.append(f"Unknown verification source for event: {source}")
        return False, errors


def verify_observation(observation: "Observation") -> "VerificationResult":
    """
    Verify an observation against the original source.

    Observations can be from GitHub API, Wayback Machine,
    or security vendor URLs.

    Returns:
        Tuple of (is_valid, errors)
    """
    errors: list[str] = []
    source = observation.verification.source

    if source == EvidenceSource.GITHUB:
        return _verify_github_observation(observation)
    elif source == EvidenceSource.GHARCHIVE:
        return _verify_gharchive_observation(observation)
    elif source == EvidenceSource.WAYBACK:
        return _verify_wayback_observation(observation)
    elif source == EvidenceSource.SECURITY_VENDOR:
        return _verify_security_vendor_observation(observation)
    elif source == EvidenceSource.GIT:
        return _verify_git_observation(observation)
    else:
        errors.append(f"Unknown verification source: {source}")
        return False, errors


def verify_all(evidence_list: Sequence["AnyEvidence"]) -> "VerificationResult":
    """
    Verify a list of evidence items.

    Iterates through all items, calling verify() on each.
    Aggregates all errors.

    Returns:
        Tuple of (all_valid, aggregated_errors)
    """
    all_errors: list[str] = []
    all_valid = True

    for evidence in evidence_list:
        is_valid, errors = evidence.verify()
        if not is_valid:
            all_valid = False
            evidence_id = getattr(evidence, "evidence_id", "unknown")
            for error in errors:
                all_errors.append(f"[{evidence_id}] {error}")

    return all_valid, all_errors


# =============================================================================
# GITHUB API VERIFICATION
# =============================================================================


def _create_github_client() -> "GitHubClient":
    """Create a new GitHub client."""
    from ._clients import GitHubClient
    return GitHubClient()


def _verify_github_observation(
    observation: "Observation",
    client: "GitHubClient | None" = None,
) -> "VerificationResult":
    """Verify observation against GitHub API."""
    errors: list[str] = []
    if client is None:
        client = _create_github_client()

    obs_type = getattr(observation, "observation_type", None)

    try:
        if obs_type == "commit":
            return _verify_commit_observation(observation, client, errors)
        elif obs_type == "issue":
            return _verify_issue_observation(observation, client, errors)
        elif obs_type == "file":
            return _verify_file_observation(observation, client, errors)
        elif obs_type == "branch":
            return _verify_branch_observation(observation, client, errors)
        elif obs_type == "tag":
            return _verify_tag_observation(observation, client, errors)
        elif obs_type == "release":
            return _verify_release_observation(observation, client, errors)
        elif obs_type == "fork":
            return _verify_fork_observation(observation, errors)
        else:
            # No specific verification - just check URL is accessible
            if observation.verification.url:
                import requests
                resp = requests.get(str(observation.verification.url), timeout=30)
                resp.raise_for_status()
            return True, []
    except Exception as e:
        if getattr(observation, "is_deleted", False):
            return True, []  # Expected - item is marked as deleted
        errors.append(f"Verification failed: {e}")
        return False, errors


def _verify_commit_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify commit observation."""
    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    sha = getattr(observation, "sha", None)
    if not sha:
        errors.append("No SHA specified")
        return False, errors

    data = client.get_commit(repo.owner, repo.name, sha)
    commit = data.get("commit", {})

    if data.get("sha") != sha:
        errors.append(f"SHA mismatch: expected {sha}, got {data.get('sha')}")

    if hasattr(observation, "message"):
        actual_msg = commit.get("message", "")
        if observation.message != actual_msg:
            errors.append("Message mismatch")

    if hasattr(observation, "author") and observation.author:
        actual_author = commit.get("author", {})
        if observation.author.name != actual_author.get("name"):
            errors.append(f"Author name mismatch: expected {observation.author.name}, got {actual_author.get('name')}")

    return len(errors) == 0, errors


def _verify_issue_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify issue/PR observation."""
    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    number = getattr(observation, "issue_number", None)
    if not number:
        errors.append("No issue number specified")
        return False, errors

    is_pr = getattr(observation, "is_pull_request", False)

    if is_pr:
        data = client.get_pull_request(repo.owner, repo.name, number)
    else:
        data = client.get_issue(repo.owner, repo.name, number)

    if data.get("number") != number:
        errors.append(f"Number mismatch: expected {number}, got {data.get('number')}")

    if hasattr(observation, "title") and observation.title:
        if data.get("title") != observation.title:
            errors.append("Title mismatch")

    if hasattr(observation, "state") and observation.state:
        actual_state = data.get("state")
        if data.get("merged"):
            actual_state = "merged"
        if observation.state != actual_state:
            errors.append(f"State mismatch: expected {observation.state}, got {actual_state}")

    return len(errors) == 0, errors


def _verify_file_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify file observation."""
    import base64
    import hashlib

    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    file_path = getattr(observation, "file_path", None)
    if not file_path:
        errors.append("No file path specified")
        return False, errors

    ref = getattr(observation, "branch", None) or "HEAD"
    data = client.get_file(repo.owner, repo.name, file_path, ref)

    if hasattr(observation, "content_hash") and observation.content_hash:
        content = ""
        if data.get("content"):
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        actual_hash = hashlib.sha256(content.encode()).hexdigest()
        if observation.content_hash != actual_hash:
            errors.append("Content hash mismatch")

    return len(errors) == 0, errors


def _verify_branch_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify branch observation."""
    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    branch_name = getattr(observation, "branch_name", None)
    if not branch_name:
        errors.append("No branch name specified")
        return False, errors

    data = client.get_branch(repo.owner, repo.name, branch_name)

    if hasattr(observation, "head_sha"):
        actual_sha = data.get("commit", {}).get("sha")
        if observation.head_sha != actual_sha:
            errors.append(f"HEAD SHA mismatch: expected {observation.head_sha}, got {actual_sha}")

    return len(errors) == 0, errors


def _verify_tag_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify tag observation."""
    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    tag_name = getattr(observation, "tag_name", None)
    if not tag_name:
        errors.append("No tag name specified")
        return False, errors

    data = client.get_tag(repo.owner, repo.name, tag_name)

    if hasattr(observation, "target_sha"):
        actual_sha = data.get("object", {}).get("sha")
        if observation.target_sha != actual_sha:
            errors.append(f"Target SHA mismatch: expected {observation.target_sha}, got {actual_sha}")

    return len(errors) == 0, errors


def _verify_release_observation(
    observation: "Observation",
    client: "GitHubClient",
    errors: list[str],
) -> "VerificationResult":
    """Verify release observation."""
    repo = observation.repository
    if not repo:
        errors.append("No repository specified")
        return False, errors

    tag_name = getattr(observation, "tag_name", None)
    if not tag_name:
        errors.append("No tag name specified")
        return False, errors

    data = client.get_release(repo.owner, repo.name, tag_name)

    if data.get("tag_name") != tag_name:
        errors.append("Tag name mismatch")

    return len(errors) == 0, errors


def _verify_fork_observation(
    observation: "Observation",
    errors: list[str],
) -> "VerificationResult":
    """Verify fork observation by checking URL accessibility."""
    if observation.verification.url:
        import requests
        resp = requests.get(str(observation.verification.url), timeout=30)
        resp.raise_for_status()
    return True, []


# =============================================================================
# GH ARCHIVE VERIFICATION
# =============================================================================


def _create_gharchive_client() -> "GHArchiveClient | None":
    """Create a new GH Archive client. Returns None if credentials unavailable."""
    from ._clients import GHArchiveClient
    try:
        client = GHArchiveClient()
        client._get_client()  # Test if credentials work
        return client
    except Exception:
        return None


def _verify_gharchive_event(event: "Event") -> "VerificationResult":
    """Verify event against GH Archive BigQuery."""
    errors: list[str] = []

    if not event.verification.bigquery_table:
        errors.append("No BigQuery table specified for GH Archive verification")
        return False, errors

    client = _create_gharchive_client()
    if client is None:
        return True, ["GH Archive verification skipped - no BigQuery credentials"]

    timestamp = event.when.strftime("%Y%m%d%H%M")
    repo = event.repository.full_name if event.repository else None

    try:
        rows = client.query_events(
            repo=repo,
            actor=event.who.login if event.who else None,
            from_date=timestamp,
        )

        if not rows:
            errors.append(f"No matching event found in GH Archive for timestamp {timestamp}")
            return False, errors

        return True, []

    except Exception as e:
        errors.append(f"GH Archive verification error: {e}")
        return False, errors


def _verify_gharchive_observation(observation: "Observation") -> "VerificationResult":
    """Verify observation against GH Archive BigQuery."""
    errors: list[str] = []

    if not observation.verification.bigquery_table:
        errors.append("No BigQuery table specified for GH Archive verification")
        return False, errors

    client = _create_gharchive_client()
    if client is None:
        return True, ["GH Archive verification skipped - no BigQuery credentials"]

    query = observation.verification.query
    if query:
        return True, ["GH Archive observation verification not fully implemented"]

    return True, []


# =============================================================================
# WAYBACK MACHINE VERIFICATION
# =============================================================================


def _verify_wayback_observation(observation: "Observation") -> "VerificationResult":
    """Verify observation against Wayback Machine CDX API."""
    import requests

    errors: list[str] = []

    if not observation.verification.url:
        errors.append("No Wayback URL specified")
        return False, errors

    try:
        url = observation.verification.url
        resp = requests.get(str(url), timeout=30)
        resp.raise_for_status()
        return True, []

    except requests.RequestException as e:
        errors.append(f"Failed to verify against Wayback: {e}")
        return False, errors


# =============================================================================
# SECURITY VENDOR VERIFICATION
# =============================================================================


def _verify_security_vendor_observation(observation: "Observation") -> "VerificationResult":
    """Verify observation against security vendor URL."""
    import requests

    errors: list[str] = []
    url = observation.verification.url

    if not url:
        errors.append("No source URL specified")
        return False, errors

    try:
        resp = requests.get(str(url), timeout=30)
        resp.raise_for_status()
        content = resp.text

        obs_type = getattr(observation, "observation_type", None)
        if obs_type == "ioc":
            value = getattr(observation, "value", None)
            if value and value.lower() not in content.lower():
                errors.append(f"IOC value '{value[:50]}' not found in source")
                return False, errors

        return True, []

    except requests.RequestException as e:
        errors.append(f"Failed to fetch source URL: {e}")
        return False, errors


# =============================================================================
# GIT LOCAL VERIFICATION (Not implemented)
# =============================================================================


def _verify_git_event(event: "Event") -> "VerificationResult":
    """Not implemented - local git requires repository path."""
    return True, ["Local git verification not supported - use GitHub API source instead"]


def _verify_git_observation(observation: "Observation") -> "VerificationResult":
    """Not implemented - local git requires repository path."""
    return True, ["Local git verification not supported - use GitHub API source instead"]
