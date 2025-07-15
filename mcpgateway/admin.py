# -*- coding: utf-8 -*-
"""Admin UI Routes for MCP Gateway.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

This module contains all the administrative UI endpoints for the MCP Gateway.
It provides a comprehensive interface for managing servers, tools, resources,
prompts, gateways, and roots through RESTful API endpoints. The module handles
all aspects of CRUD operations for these entities, including creation,
reading, updating, deletion, and status toggling.

All endpoints in this module require authentication, which is enforced via
the require_auth or require_basic_auth dependency. The module integrates with
various services to perform the actual business logic operations on the
underlying data.
"""

# Standard
import json
import logging
import time
from typing import Any, Dict, List, Union

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.schemas import (
    GatewayCreate,
    GatewayRead,
    GatewayTestRequest,
    GatewayTestResponse,
    GatewayUpdate,
    PromptCreate,
    PromptMetrics,
    PromptRead,
    PromptUpdate,
    ResourceCreate,
    ResourceMetrics,
    ResourceRead,
    ResourceUpdate,
    ServerCreate,
    ServerMetrics,
    ServerRead,
    ServerUpdate,
    ToolCreate,
    ToolMetrics,
    ToolRead,
    ToolUpdate,
)
from mcpgateway.services.gateway_service import GatewayConnectionError, GatewayService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerNotFoundError, ServerService
from mcpgateway.services.tool_service import (
    ToolError,
    ToolNameConflictError,
    ToolService,
)
from mcpgateway.utils.create_jwt_token import get_jwt_token
from mcpgateway.utils.retry_manager import ResilientHttpClient
from mcpgateway.utils.verify_credentials import require_auth, require_basic_auth
from mcpgateway.utils.error_formatter import ErrorFormatter

# Initialize services
server_service = ServerService()
tool_service = ToolService()
prompt_service = PromptService()
gateway_service = GatewayService()
resource_service = ResourceService()
root_service = RootService()

# Set up basic authentication
logger = logging.getLogger("mcpgateway")

admin_router = APIRouter(prefix="/admin", tags=["Admin UI"])

####################
# Admin UI Routes  #
####################


@admin_router.get("/servers", response_model=List[ServerRead])
async def admin_list_servers(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ServerRead]:
    """
    List servers for the admin UI with an option to include inactive servers.

    Args:
        include_inactive (bool): Whether to include inactive servers.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        List[ServerRead]: A list of server records.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ServerRead
        >>> 
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> 
        >>> # Mock server service
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.schemas import ServerMetrics
        >>> mock_metrics = ServerMetrics(
        ...     total_executions=10,
        ...     successful_executions=8,
        ...     failed_executions=2,
        ...     failure_rate=0.2,
        ...     min_response_time=0.1,
        ...     max_response_time=2.0,
        ...     avg_response_time=0.5,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_server = ServerRead(
        ...     id="server-1",
        ...     name="Test Server",
        ...     description="A test server",
        ...     icon="test-icon.png",
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     associated_tools=["tool1", "tool2"],
        ...     associated_resources=[1, 2],
        ...     associated_prompts=[1],
        ...     metrics=mock_metrics
        ... )
        >>> 
        >>> # Mock the server_service.list_servers method
        >>> original_list_servers = server_service.list_servers
        >>> server_service.list_servers = AsyncMock(return_value=[mock_server])
        >>> 
        >>> # Test the function
        >>> async def test_admin_list_servers():
        ...     result = await admin_list_servers(
        ...         include_inactive=False,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return len(result) > 0 and isinstance(result[0], dict)
        >>> 
        >>> # Run the test
        >>> asyncio.run(test_admin_list_servers())
        True
        >>> 
        >>> # Restore original method
        >>> server_service.list_servers = original_list_servers
        >>> 
        >>> # Additional test for empty server list
        >>> server_service.list_servers = AsyncMock(return_value=[])
        >>> async def test_admin_list_servers_empty():
        ...     result = await admin_list_servers(
        ...         include_inactive=True,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return result == []
        >>> asyncio.run(test_admin_list_servers_empty())
        True
        >>> server_service.list_servers = original_list_servers
        >>> 
        >>> # Additional test for exception handling
        >>> import pytest
        >>> from fastapi import HTTPException
        >>> async def test_admin_list_servers_exception():
        ...     server_service.list_servers = AsyncMock(side_effect=Exception("Test error"))
        ...     try:
        ...         await admin_list_servers(False, mock_db, mock_user)
        ...     except Exception as e:
        ...         return str(e) == "Test error"
        ...     return False
        >>> asyncio.run(test_admin_list_servers_exception())
        True
    """
    logger.debug(f"User {user} requested server list")
    servers = await server_service.list_servers(db, include_inactive=include_inactive)
    return [server.model_dump(by_alias=True) for server in servers]


@admin_router.get("/servers/{server_id}", response_model=ServerRead)
async def admin_get_server(server_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ServerRead:
    """
    Retrieve server details for the admin UI.

    Args:
        server_id (str): The ID of the server to retrieve.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        ServerRead: The server details.

    Raises:
        HTTPException: If the server is not found.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ServerRead
        >>> from mcpgateway.services.server_service import ServerNotFoundError
        >>> from fastapi import HTTPException
        >>> 
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> server_id = "test-server-1"
        >>> 
        >>> # Mock server response
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.schemas import ServerMetrics
        >>> mock_metrics = ServerMetrics(
        ...     total_executions=5,
        ...     successful_executions=4,
        ...     failed_executions=1,
        ...     failure_rate=0.2,
        ...     min_response_time=0.2,
        ...     max_response_time=1.5,
        ...     avg_response_time=0.8,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_server = ServerRead(
        ...     id=server_id,
        ...     name="Test Server",
        ...     description="A test server",
        ...     icon="test-icon.png",
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     associated_tools=["tool1"],
        ...     associated_resources=[1],
        ...     associated_prompts=[1],
        ...     metrics=mock_metrics
        ... )
        >>> 
        >>> # Mock the server_service.get_server method
        >>> original_get_server = server_service.get_server
        >>> server_service.get_server = AsyncMock(return_value=mock_server)
        >>> 
        >>> # Test successful retrieval
        >>> async def test_admin_get_server_success():
        ...     result = await admin_get_server(
        ...         server_id=server_id,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return isinstance(result, dict) and result.get('id') == server_id
        >>> 
        >>> # Run the test
        >>> asyncio.run(test_admin_get_server_success())
        True
        >>> 
        >>> # Test server not found scenario
        >>> server_service.get_server = AsyncMock(side_effect=ServerNotFoundError("Server not found"))
        >>> 
        >>> async def test_admin_get_server_not_found():
        ...     try:
        ...         await admin_get_server(
        ...             server_id="nonexistent",
        ...             db=mock_db,
        ...             user=mock_user
        ...         )
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404
        >>> 
        >>> # Run the not found test
        >>> asyncio.run(test_admin_get_server_not_found())
        True
        >>> 
        >>> # Restore original method
        >>> server_service.get_server = original_get_server
    """
    try:
        logger.debug(f"User {user} requested details for server ID {server_id}")
        server = await server_service.get_server(db, server_id)
        return server.model_dump(by_alias=True)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@admin_router.post("/servers", response_model=ServerRead)
async def admin_add_server(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Add a new server via the admin UI.

    This endpoint processes form data to create a new server entry in the database.
    It handles exceptions gracefully and logs any errors that occur during server
    registration.

    Expects form fields:
      - name (required): The name of the server
      - description (optional): A description of the server's purpose
      - icon (optional): URL or path to the server's icon
      - associatedTools (optional, comma-separated): Tools associated with this server
      - associatedResources (optional, comma-separated): Resources associated with this server
      - associatedPrompts (optional, comma-separated): Prompts associated with this server

    Args:
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> 
        >>> # Mock form data for successful server creation
        >>> form_data = FormData([
        ...     ("name", "Test Server"),
        ...     ("description", "A test server"),
        ...     ("icon", "test-icon.png"),
        ...     ("associatedTools", "tool1"),
        ...     ("associatedTools", "tool2"),
        ...     ("associatedResources", "resource1"),
        ...     ("associatedPrompts", "prompt1"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> 
        >>> # Mock request with form data
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": "/test"}
        >>> 
        >>> # Mock server service
        >>> original_register_server = server_service.register_server
        >>> server_service.register_server = AsyncMock()
        >>> 
        >>> # Test successful server addition
        >>> async def test_admin_add_server_success():
        ...     result = await admin_add_server(
        ...         request=mock_request,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303
        >>> 
        >>> # Run the test
        >>> asyncio.run(test_admin_add_server_success())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Test Server"),
        ...     ("description", "A test server"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_add_server_inactive():
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and "include_inactive=true" in result.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_add_server_inactive())
        True
        >>> 
        >>> # Test exception handling - should still return redirect
        >>> async def test_admin_add_server_exception():
        ...     server_service.register_server = AsyncMock(side_effect=Exception("Test error"))
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_add_server_exception())
        True
        >>> 
        >>> # Test with minimal form data
        >>> form_data_minimal = FormData([("name", "Minimal Server")])
        >>> mock_request.form = AsyncMock(return_value=form_data_minimal)
        >>> server_service.register_server = AsyncMock()
        >>> 
        >>> async def test_admin_add_server_minimal():
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse)
        >>> 
        >>> asyncio.run(test_admin_add_server_minimal())
        True
        >>> 
        >>> # Restore original method
        >>> server_service.register_server = original_register_server
    """
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        logger.debug(f"User {user} is adding a new server with name: {form['name']}")

        server = ServerCreate(
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(form.getlist("associatedTools")),
            associated_resources=form.get("associatedResources"),
            associated_prompts=form.get("associatedPrompts"),
        )
        await server_service.register_server(db, server)

        root_path = request.scope.get("root_path", "")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
        return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)
    except Exception as e:
        logger.error(f"Error adding server: {e}")

        root_path = request.scope.get("root_path", "")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
        return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)


@admin_router.post("/resources")
async def admin_add_resource(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Add a resource via the admin UI.

    Expects form fields:
      - uri
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("uri", "test://resource1"),
        ...     ("name", "Test Resource"),
        ...     ("description", "A test resource"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Sample content"),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_register_resource = resource_service.register_resource
        >>> resource_service.register_resource = AsyncMock()
        >>> 
        >>> async def test_admin_add_resource():
        ...     response = await admin_add_resource(mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_add_resource())
        True
        >>> resource_service.register_resource = original_register_resource
    """
    logger.debug(f"User {user} is adding a new resource")
    form = await request.form()
    resource = ResourceCreate(
        uri=form["uri"],
        name=form["name"],
        description=form.get("description"),
        mime_type=form.get("mimeType"),
        template=form.get("template"),
        content=form["content"],
    )
    await resource_service.register_resource(db, resource)
    root_path = request.scope.get("root_path", "")
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.post("/resources/{uri:path}/edit")
async def admin_edit_resource(
    uri: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Edit a resource via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        uri: Resource URI.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("name", "Updated Resource"),
        ...     ("description", "Updated description"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Updated content"),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_update_resource = resource_service.update_resource
        >>> resource_service.update_resource = AsyncMock()
        >>> 
        >>> async def test_admin_edit_resource():
        ...     response = await admin_edit_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_edit_resource())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Updated Resource"),
        ...     ("description", "Updated description"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Updated content"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_edit_resource_inactive():
        ...     response = await admin_edit_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_edit_resource_inactive())
        True
        >>> resource_service.update_resource = original_update_resource
    """
    logger.debug(f"User {user} is editing resource URI {uri}")
    form = await request.form()
    resource = ResourceUpdate(
        name=form["name"],
        description=form.get("description"),
        mime_type=form.get("mimeType"),
        content=form["content"],
    )
    await resource_service.update_resource(db, uri, resource)
    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.post("/resources/{uri:path}/delete")
async def admin_delete_resource(uri: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a resource via the admin UI.

    This endpoint permanently removes a resource from the database using its URI.
    The operation is irreversible and should be used with caution. It requires
    user authentication and logs the deletion attempt.

    Args:
        uri (str): The URI of the resource to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the resources section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_delete_resource = resource_service.delete_resource
        >>> resource_service.delete_resource = AsyncMock()
        >>> 
        >>> async def test_admin_delete_resource():
        ...     response = await admin_delete_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_delete_resource())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_delete_resource_inactive():
        ...     response = await admin_delete_resource("test://resource1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_delete_resource_inactive())
        True
        >>> resource_service.delete_resource = original_delete_resource
    """
    logger.debug(f"User {user} is deleting resource URI {uri}")
    await resource_service.delete_resource(db, uri)
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.post("/resources/{resource_id}/toggle")
async def admin_toggle_resource(
    resource_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a resource's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a resource.
    It expects a form field 'activate' with value "true" to activate the resource
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        resource_id (int): The ID of the resource whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard resources section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_toggle_resource_status = resource_service.toggle_resource_status
        >>> resource_service.toggle_resource_status = AsyncMock()
        >>> 
        >>> async def test_admin_toggle_resource():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_toggle_resource())
        True
        >>> 
        >>> # Test with activate=false
        >>> form_data_deactivate = FormData([
        ...     ("activate", "false"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_deactivate)
        >>> 
        >>> async def test_admin_toggle_resource_deactivate():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_toggle_resource_deactivate())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_toggle_resource_inactive():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_toggle_resource_inactive())
        True
        >>> 
        >>> # Test exception handling
        >>> resource_service.toggle_resource_status = AsyncMock(side_effect=Exception("Test error"))
        >>> form_data_error = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_error)
        >>> 
        >>> async def test_admin_toggle_resource_exception():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_toggle_resource_exception())
        True
        >>> resource_service.toggle_resource_status = original_toggle_resource_status
    """
    logger.debug(f"User {user} is toggling resource ID {resource_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await resource_service.toggle_resource_status(db, resource_id, activate)
    except Exception as e:
        logger.error(f"Error toggling resource status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.get("/prompts/{name}")
async def admin_get_prompt(name: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, Any]:
    """Get prompt details for the admin UI.

    Args:
        name: Prompt name.
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary with prompt details.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import PromptRead
        >>> from datetime import datetime, timezone
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> prompt_name = "test-prompt"
        >>> 
        >>> # Mock prompt details
        >>> from mcpgateway.schemas import PromptMetrics
        >>> mock_metrics = PromptMetrics(
        ...     total_executions=3,
        ...     successful_executions=3,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.1,
        ...     max_response_time=0.5,
        ...     avg_response_time=0.3,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_prompt_details = {
        ...     "id": 1,
        ...     "name": prompt_name,
        ...     "description": "A test prompt",
        ...     "template": "Hello {{name}}!",
        ...     "arguments": [{"name": "name", "type": "string"}],
        ...     "created_at": datetime.now(timezone.utc),
        ...     "updated_at": datetime.now(timezone.utc),
        ...     "is_active": True,
        ...     "metrics": mock_metrics
        ... }
        >>> 
        >>> original_get_prompt_details = prompt_service.get_prompt_details
        >>> prompt_service.get_prompt_details = AsyncMock(return_value=mock_prompt_details)
        >>> 
        >>> async def test_admin_get_prompt():
        ...     result = await admin_get_prompt(prompt_name, mock_db, mock_user)
        ...     return isinstance(result, dict) and result.get("name") == prompt_name
        >>> 
        >>> asyncio.run(test_admin_get_prompt())
        True
        >>> prompt_service.get_prompt_details = original_get_prompt_details
    """
    logger.debug(f"User {user} requested details for prompt name {name}")
    prompt_details = await prompt_service.get_prompt_details(db, name)

    prompt = PromptRead.model_validate(prompt_details)
    return prompt.model_dump(by_alias=True)


@admin_router.post("/prompts")
async def admin_add_prompt(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """Add a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("name", "Test Prompt"),
        ...     ("description", "A test prompt"),
        ...     ("template", "Hello {{name}}!"),
        ...     ("arguments", '[{"name": "name", "type": "string"}]'),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_register_prompt = prompt_service.register_prompt
        >>> prompt_service.register_prompt = AsyncMock()
        >>> 
        >>> async def test_admin_add_prompt():
        ...     response = await admin_add_prompt(mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_add_prompt())
        True
        >>> prompt_service.register_prompt = original_register_prompt
    """
    logger.debug(f"User {user} is adding a new prompt")
    form = await request.form()
    args_json = form.get("arguments") or "[]"
    arguments = json.loads(args_json)
    prompt = PromptCreate(
        name=form["name"],
        description=form.get("description"),
        template=form["template"],
        arguments=arguments,
    )
    await prompt_service.register_prompt(db, prompt)

    root_path = request.scope.get("root_path", "")
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/prompts/{name}/edit")
async def admin_edit_prompt(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """Edit a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        name: Prompt name.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> prompt_name = "test-prompt"
        >>> form_data = FormData([
        ...     ("name", "Updated Prompt"),
        ...     ("description", "Updated description"),
        ...     ("template", "Hello {{name}}, welcome!"),
        ...     ("arguments", '[{"name": "name", "type": "string"}]'),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_update_prompt = prompt_service.update_prompt
        >>> prompt_service.update_prompt = AsyncMock()
        >>> 
        >>> async def test_admin_edit_prompt():
        ...     response = await admin_edit_prompt(prompt_name, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_edit_prompt())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Updated Prompt"),
        ...     ("template", "Hello {{name}}!"),
        ...     ("arguments", "[]"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_edit_prompt_inactive():
        ...     response = await admin_edit_prompt(prompt_name, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_edit_prompt_inactive())
        True
        >>> prompt_service.update_prompt = original_update_prompt
    """
    logger.debug(f"User {user} is editing prompt name {name}")
    form = await request.form()
    args_json = form.get("arguments") or "[]"
    arguments = json.loads(args_json)
    prompt = PromptUpdate(
        name=form["name"],
        description=form.get("description"),
        template=form["template"],
        arguments=arguments,
    )
    await prompt_service.update_prompt(db, name, prompt)

    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")

    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/prompts/{name}/delete")
async def admin_delete_prompt(name: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a prompt via the admin UI.

    This endpoint permanently deletes a prompt from the database using its name.
    Deletion is irreversible and requires authentication. All actions are logged
    for administrative auditing.

    Args:
        name (str): The name of the prompt to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the prompts section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_delete_prompt = prompt_service.delete_prompt
        >>> prompt_service.delete_prompt = AsyncMock()
        >>> 
        >>> async def test_admin_delete_prompt():
        ...     response = await admin_delete_prompt("test-prompt", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_delete_prompt())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_delete_prompt_inactive():
        ...     response = await admin_delete_prompt("test-prompt", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_delete_prompt_inactive())
        True
        >>> prompt_service.delete_prompt = original_delete_prompt
    """
    logger.debug(f"User {user} is deleting prompt name {name}")
    await prompt_service.delete_prompt(db, name)
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/prompts/{prompt_id}/toggle")
async def admin_toggle_prompt(
    prompt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a prompt's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a prompt.
    It expects a form field 'activate' with value "true" to activate the prompt
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        prompt_id (int): The ID of the prompt whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard prompts section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_toggle_prompt_status = prompt_service.toggle_prompt_status
        >>> prompt_service.toggle_prompt_status = AsyncMock()
        >>> 
        >>> async def test_admin_toggle_prompt():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_toggle_prompt())
        True
        >>> 
        >>> # Test with activate=false
        >>> form_data_deactivate = FormData([
        ...     ("activate", "false"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_deactivate)
        >>> 
        >>> async def test_admin_toggle_prompt_deactivate():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_toggle_prompt_deactivate())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_toggle_prompt_inactive():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_toggle_prompt_inactive())
        True
        >>> 
        >>> # Test exception handling
        >>> prompt_service.toggle_prompt_status = AsyncMock(side_effect=Exception("Test error"))
        >>> form_data_error = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_error)
        >>> 
        >>> async def test_admin_toggle_prompt_exception():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> asyncio.run(test_admin_toggle_prompt_exception())
        True
        >>> prompt_service.toggle_prompt_status = original_toggle_prompt_status
    """
    logger.debug(f"User {user} is toggling prompt ID {prompt_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await prompt_service.toggle_prompt_status(db, prompt_id, activate)
    except Exception as e:
        logger.error(f"Error toggling prompt status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/roots")
async def admin_add_root(request: Request, user: str = Depends(require_auth)) -> RedirectResponse:
    """Add a new root via the admin UI.

    Expects form fields:
      - path
      - name (optional)

    Args:
        request: FastAPI request containing form data.
        user: Authenticated user.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("uri", "test://root1"),
        ...     ("name", "Test Root"),
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_add_root = root_service.add_root
        >>> root_service.add_root = AsyncMock()
        >>> 
        >>> async def test_admin_add_root():
        ...     response = await admin_add_root(mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_add_root())
        True
        >>> root_service.add_root = original_add_root
    """
    logger.debug(f"User {user} is adding a new root")
    form = await request.form()
    uri = form["uri"]
    name = form.get("name")
    await root_service.add_root(uri, name)
    root_path = request.scope.get("root_path", "")
    return RedirectResponse(f"{root_path}/admin#roots", status_code=303)


@admin_router.post("/roots/{uri:path}/delete")
async def admin_delete_root(uri: str, request: Request, user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a root via the admin UI.

    This endpoint removes a registered root URI from the system. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for audit purposes.

    Args:
        uri (str): The URI of the root to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the roots section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> 
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>> 
        >>> original_remove_root = root_service.remove_root
        >>> root_service.remove_root = AsyncMock()
        >>> 
        >>> async def test_admin_delete_root():
        ...     response = await admin_delete_root("test://root1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>> 
        >>> import asyncio; asyncio.run(test_admin_delete_root())
        True
        >>> 
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>> 
        >>> async def test_admin_delete_root_inactive():
        ...     response = await admin_delete_root("test://root1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>> 
        >>> asyncio.run(test_admin_delete_root_inactive())
        True
        >>> root_service.remove_root = original_remove_root
    """
    logger.debug(f"User {user} is deleting root URI {uri}")
    await root_service.remove_root(uri)
    form = await request.form()
    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#roots", status_code=303)
    return RedirectResponse(f"{root_path}/admin#roots", status_code=303)


# Metrics
MetricsDict = Dict[str, Union[ToolMetrics, ResourceMetrics, ServerMetrics, PromptMetrics]]


@admin_router.get("/metrics", response_model=MetricsDict)
async def admin_get_metrics(
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> MetricsDict:
    """
    Retrieve aggregate metrics for all entity types via the admin UI.

    This endpoint collects and returns usage metrics for tools, resources, servers,
    and prompts. The metrics are retrieved by calling the aggregate_metrics method
    on each respective service, which compiles statistics about usage patterns,
    success rates, and other relevant metrics for administrative monitoring
    and analysis purposes.

    Args:
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        MetricsDict: A dictionary containing the aggregated metrics for tools,
        resources, servers, and prompts. Each value is a Pydantic model instance
        specific to the entity type.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ToolMetrics, ResourceMetrics, ServerMetrics, PromptMetrics
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> 
        >>> mock_tool_metrics = ToolMetrics(
        ...     total_executions=10,
        ...     successful_executions=9,
        ...     failed_executions=1,
        ...     failure_rate=0.1,
        ...     min_response_time=0.05,
        ...     max_response_time=1.0,
        ...     avg_response_time=0.3,
        ...     last_execution_time=None
        ... )
        >>> mock_resource_metrics = ResourceMetrics(
        ...     total_executions=5,
        ...     successful_executions=5,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.1,
        ...     max_response_time=0.5,
        ...     avg_response_time=0.2,
        ...     last_execution_time=None
        ... )
        >>> mock_server_metrics = ServerMetrics(
        ...     total_executions=7,
        ...     successful_executions=7,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.2,
        ...     max_response_time=0.7,
        ...     avg_response_time=0.4,
        ...     last_execution_time=None
        ... )
        >>> mock_prompt_metrics = PromptMetrics(
        ...     total_executions=3,
        ...     successful_executions=3,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.15,
        ...     max_response_time=0.6,
        ...     avg_response_time=0.35,
        ...     last_execution_time=None
        ... )
        >>> 
        >>> original_aggregate_metrics_tool = tool_service.aggregate_metrics
        >>> original_aggregate_metrics_resource = resource_service.aggregate_metrics
        >>> original_aggregate_metrics_server = server_service.aggregate_metrics
        >>> original_aggregate_metrics_prompt = prompt_service.aggregate_metrics
        >>> 
        >>> tool_service.aggregate_metrics = AsyncMock(return_value=mock_tool_metrics)
        >>> resource_service.aggregate_metrics = AsyncMock(return_value=mock_resource_metrics)
        >>> server_service.aggregate_metrics = AsyncMock(return_value=mock_server_metrics)
        >>> prompt_service.aggregate_metrics = AsyncMock(return_value=mock_prompt_metrics)
        >>> 
        >>> async def test_admin_get_metrics():
        ...     result = await admin_get_metrics(mock_db, mock_user)
        ...     return (
        ...         isinstance(result, dict) and
        ...         result.get("tools") == mock_tool_metrics and
        ...         result.get("resources") == mock_resource_metrics and
        ...         result.get("servers") == mock_server_metrics and
        ...         result.get("prompts") == mock_prompt_metrics
        ...     )
        >>> 
        >>> import asyncio; asyncio.run(test_admin_get_metrics())
        True
        >>> 
        >>> tool_service.aggregate_metrics = original_aggregate_metrics_tool
        >>> resource_service.aggregate_metrics = original_aggregate_metrics_resource
        >>> server_service.aggregate_metrics = original_aggregate_metrics_server
        >>> prompt_service.aggregate_metrics = original_aggregate_metrics_prompt
    """
    logger.debug(f"User {user} requested aggregate metrics")
    tool_metrics = await tool_service.aggregate_metrics(db)
    resource_metrics = await resource_service.aggregate_metrics(db)
    server_metrics = await server_service.aggregate_metrics(db)
    prompt_metrics = await prompt_service.aggregate_metrics(db)

    return {
        "tools": tool_metrics,
        "resources": resource_metrics,
        "servers": server_metrics,
        "prompts": prompt_metrics,
    }


@admin_router.post("/metrics/reset", response_model=Dict[str, object])
async def admin_reset_metrics(db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, object]:
    """
    Reset all metrics for tools, resources, servers, and prompts.
    Each service must implement its own reset_metrics method.

    Args:
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, object]: A dictionary containing a success message and status.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> 
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> 
        >>> original_reset_metrics_tool = tool_service.reset_metrics
        >>> original_reset_metrics_resource = resource_service.reset_metrics
        >>> original_reset_metrics_server = server_service.reset_metrics
        >>> original_reset_metrics_prompt = prompt_service.reset_metrics
        >>> 
        >>> tool_service.reset_metrics = AsyncMock()
        >>> resource_service.reset_metrics = AsyncMock()
        >>> server_service.reset_metrics = AsyncMock()
        >>> prompt_service.reset_metrics = AsyncMock()
        >>> 
        >>> async def test_admin_reset_metrics():
        ...     result = await admin_reset_metrics(mock_db, mock_user)
        ...     return result == {"message": "All metrics reset successfully", "success": True}
        >>> 
        >>> import asyncio; asyncio.run(test_admin_reset_metrics())
        True
        >>> 
        >>> tool_service.reset_metrics = original_reset_metrics_tool
        >>> resource_service.reset_metrics = original_reset_metrics_resource
        >>> server_service.reset_metrics = original_reset_metrics_server
        >>> prompt_service.reset_metrics = original_reset_metrics_prompt
    """
    logger.debug(f"User {user} requested to reset all metrics")
    await tool_service.reset_metrics(db)
    await resource_service.reset_metrics(db)
    await server_service.reset_metrics(db)
    await prompt_service.reset_metrics(db)
    return {"message": "All metrics reset successfully", "success": True}


@admin_router.post("/gateways/test", response_model=GatewayTestResponse)
async def admin_test_gateway(request: GatewayTestRequest, user: str = Depends(require_auth)) -> GatewayTestResponse:
    """
    Test a gateway by sending a request to its URL.
    This endpoint allows administrators to test the connectivity and response

    Args:
        request (GatewayTestRequest): The request object containing the gateway URL and request details.
        user (str): Authenticated user dependency.

    Returns:
        GatewayTestResponse: The response from the gateway, including status code, latency, and body

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import GatewayTestRequest, GatewayTestResponse
        >>> from fastapi import Request
        >>> import httpx
        >>> 
        >>> mock_user = "test_user"
        >>> mock_request = GatewayTestRequest(
        ...     base_url="https://api.example.com",
        ...     path="/test",
        ...     method="GET",
        ...     headers={},
        ...     body=None
        ... )
        >>> 
        >>> # Mock ResilientHttpClient to simulate a successful response
        >>> class MockResponse:
        ...     def __init__(self):
        ...         self.status_code = 200
        ...         self._json = {"message": "success"}
        ...     def json(self):
        ...         return self._json
        ...     @property
        ...     def text(self):
        ...         return str(self._json)
        >>> 
        >>> class MockClient:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         return MockResponse()
        >>> 
        >>> from unittest.mock import patch
        >>> 
        >>> async def test_admin_test_gateway():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>> 
        >>> result = asyncio.run(test_admin_test_gateway())
        >>> result
        True
        >>> 
        >>> # Test with JSON decode error
        >>> class MockResponseTextOnly:
        ...     def __init__(self):
        ...         self.status_code = 200
        ...         self.text = "plain text response"
        ...     def json(self):
        ...         raise json.JSONDecodeError("Invalid JSON", "doc", 0)
        >>> 
        >>> class MockClientTextOnly:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         return MockResponseTextOnly()
        >>> 
        >>> async def test_admin_test_gateway_text_response():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClientTextOnly()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.body.get("details") == "plain text response"
        >>> 
        >>> asyncio.run(test_admin_test_gateway_text_response())
        True
        >>> 
        >>> # Test with network error
        >>> class MockClientError:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         raise httpx.RequestError("Network error")
        >>> 
        >>> async def test_admin_test_gateway_network_error():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClientError()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return response.status_code == 502 and "Network error" in str(response.body)
        >>> 
        >>> asyncio.run(test_admin_test_gateway_network_error())
        True
        >>> 
        >>> # Test with POST method and body
        >>> mock_request_post = GatewayTestRequest(
        ...     base_url="https://api.example.com",
        ...     path="/test",
        ...     method="POST",
        ...     headers={"Content-Type": "application/json"},
        ...     body={"test": "data"}
        ... )
        >>> 
        >>> async def test_admin_test_gateway_post():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request_post, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>> 
        >>> asyncio.run(test_admin_test_gateway_post())
        True
        >>> 
        >>> # Test URL path handling with trailing slashes
        >>> mock_request_trailing = GatewayTestRequest(
        ...     base_url="https://api.example.com/",
        ...     path="/test/",
        ...     method="GET",
        ...     headers={},
        ...     body=None
        ... )
        >>> 
        >>> async def test_admin_test_gateway_trailing_slash():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request_trailing, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>> 
        >>> asyncio.run(test_admin_test_gateway_trailing_slash())
        True
    """
    full_url = str(request.base_url).rstrip("/") + "/" + request.path.lstrip("/")
    full_url = full_url.rstrip("/")
    logger.debug(f"User {user} testing server at {request.base_url}.")
    try:
        start_time = time.monotonic()
        async with ResilientHttpClient(client_args={"timeout": settings.federation_timeout, "verify": not settings.skip_ssl_verify}) as client:
            response = await client.request(method=request.method.upper(), url=full_url, headers=request.headers, json=request.body)
        latency_ms = int((time.monotonic() - start_time) * 1000)
        try:
            response_body: Union[dict, str] = response.json()
        except json.JSONDecodeError:
            response_body = {"details": response.text}

        return GatewayTestResponse(status_code=response.status_code, latency_ms=latency_ms, body=response_body)

    except httpx.RequestError as e:
        logger.warning(f"Gateway test failed: {e}")
        latency_ms = int((time.monotonic() - start_time) * 1000)
        return GatewayTestResponse(status_code=502, latency_ms=latency_ms, body={"error": "Request failed", "details": str(e)})
