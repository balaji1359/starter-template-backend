"""Application monitoring utilities.

This module provides monitoring capabilities for the application including:
- Health checks
- Metrics collection
- Performance monitoring
- System resource monitoring
- Application state tracking
"""

import asyncio
import logging
import psutil
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

from app.core.database import db_manager
from app.core.config import settings

logger = logging.getLogger("app.monitoring")


@dataclass
class HealthStatus:
    """Health check status."""
    service: str
    status: str
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Optional[Dict[str, Any]] = None
    duration_ms: Optional[float] = None


@dataclass
class SystemMetrics:
    """System resource metrics."""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_sent_mb: float
    network_recv_mb: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ApplicationMetrics:
    """Application-specific metrics."""
    active_connections: int
    request_count: int
    error_count: int
    avg_response_time_ms: float
    memory_usage_mb: float
    uptime_seconds: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MetricsCollector:
    """Collects and manages application metrics."""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.response_times: List[float] = []
        self.max_response_times = 1000  # Keep last 1000 response times
    
    def record_request(self, duration_ms: float, is_error: bool = False) -> None:
        """Record request metrics.
        
        Args:
            duration_ms: Request duration in milliseconds
            is_error: Whether the request resulted in an error
        """
        self.request_count += 1
        
        if is_error:
            self.error_count += 1
        
        # Store response time
        self.response_times.append(duration_ms)
        
        # Keep only recent response times to prevent memory growth
        if len(self.response_times) > self.max_response_times:
            self.response_times = self.response_times[-self.max_response_times:]
    
    def get_application_metrics(self) -> ApplicationMetrics:
        """Get current application metrics.
        
        Returns:
            ApplicationMetrics: Current application metrics
        """
        avg_response_time = (
            sum(self.response_times) / len(self.response_times)
            if self.response_times else 0.0
        )
        
        uptime = time.time() - self.start_time
        
        # Get current process memory usage
        process = psutil.Process()
        memory_usage_mb = process.memory_info().rss / 1024 / 1024
        
        return ApplicationMetrics(
            active_connections=0,  # Would need connection pool metrics
            request_count=self.request_count,
            error_count=self.error_count,
            avg_response_time_ms=avg_response_time,
            memory_usage_mb=memory_usage_mb,
            uptime_seconds=uptime
        )
    
    def reset_counters(self) -> None:
        """Reset metric counters."""
        self.request_count = 0
        self.error_count = 0
        self.response_times.clear()


class HealthChecker:
    """Performs health checks on application components."""
    
    def __init__(self):
        self.checks: Dict[str, Callable] = {}
        self.register_default_checks()
    
    def register_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function.
        
        Args:
            name: Name of the health check
            check_func: Async function that performs the check
        """
        self.checks[name] = check_func
        logger.info(f"Registered health check: {name}")
    
    def register_default_checks(self) -> None:
        """Register default health checks."""
        self.register_check("database", self._check_database)
        self.register_check("system", self._check_system_resources)
        self.register_check("application", self._check_application)
    
    async def _check_database(self) -> HealthStatus:
        """Check database connectivity."""
        start_time = time.time()
        
        try:
            health_result = await db_manager.health_check()
            duration_ms = (time.time() - start_time) * 1000
            
            if health_result.get("status") == "healthy":
                return HealthStatus(
                    service="database",
                    status="healthy",
                    message="Database connection successful",
                    duration_ms=duration_ms,
                    details=health_result
                )
            else:
                return HealthStatus(
                    service="database",
                    status="unhealthy",
                    message=health_result.get("error", "Database check failed"),
                    duration_ms=duration_ms,
                    details=health_result
                )
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Database health check failed: {e}")
            
            return HealthStatus(
                service="database",
                status="unhealthy",
                message=f"Database connection failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )
    
    async def _check_system_resources(self) -> HealthStatus:
        """Check system resource usage."""
        start_time = time.time()
        
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Define thresholds
            cpu_threshold = 90.0
            memory_threshold = 90.0
            disk_threshold = 95.0
            
            issues = []
            if cpu_percent > cpu_threshold:
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            
            if memory.percent > memory_threshold:
                issues.append(f"High memory usage: {memory.percent:.1f}%")
            
            if disk.percent > disk_threshold:
                issues.append(f"High disk usage: {disk.percent:.1f}%")
            
            duration_ms = (time.time() - start_time) * 1000
            
            if issues:
                return HealthStatus(
                    service="system",
                    status="warning",
                    message="; ".join(issues),
                    duration_ms=duration_ms,
                    details={
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "disk_percent": disk.percent
                    }
                )
            else:
                return HealthStatus(
                    service="system",
                    status="healthy",
                    message="System resources within normal limits",
                    duration_ms=duration_ms,
                    details={
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "disk_percent": disk.percent
                    }
                )
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"System health check failed: {e}")
            
            return HealthStatus(
                service="system",
                status="unhealthy",
                message=f"System check failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )
    
    async def _check_application(self) -> HealthStatus:
        """Check application-specific health."""
        start_time = time.time()
        
        try:
            # Check basic application functionality
            # This could include checking caches, queues, etc.
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthStatus(
                service="application",
                status="healthy",
                message="Application is running normally",
                duration_ms=duration_ms,
                details={
                    "environment": settings.ENVIRONMENT,
                    "version": settings.VERSION
                }
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Application health check failed: {e}")
            
            return HealthStatus(
                service="application",
                status="unhealthy",
                message=f"Application check failed: {str(e)}",
                duration_ms=duration_ms,
                details={"error": str(e)}
            )
    
    async def run_all_checks(self) -> Dict[str, HealthStatus]:
        """Run all registered health checks.
        
        Returns:
            Dict[str, HealthStatus]: Results of all health checks
        """
        results = {}
        
        # Run all checks concurrently
        tasks = {
            name: check_func() 
            for name, check_func in self.checks.items()
        }
        
        completed_tasks = await asyncio.gather(
            *tasks.values(), 
            return_exceptions=True
        )
        
        for (name, _), result in zip(tasks.items(), completed_tasks):
            if isinstance(result, Exception):
                logger.error(f"Health check '{name}' failed with exception: {result}")
                results[name] = HealthStatus(
                    service=name,
                    status="unhealthy",
                    message=f"Health check failed: {str(result)}",
                    details={"error": str(result)}
                )
            else:
                results[name] = result
        
        return results
    
    async def get_overall_health(self) -> Dict[str, Any]:
        """Get overall application health status.
        
        Returns:
            Dict[str, Any]: Overall health summary
        """
        check_results = await self.run_all_checks()
        
        # Determine overall status
        statuses = [result.status for result in check_results.values()]
        
        if "unhealthy" in statuses:
            overall_status = "unhealthy"
        elif "warning" in statuses:
            overall_status = "warning"
        else:
            overall_status = "healthy"
        
        # Calculate total checks and failures
        total_checks = len(check_results)
        healthy_checks = sum(1 for status in statuses if status == "healthy")
        warning_checks = sum(1 for status in statuses if status == "warning")
        unhealthy_checks = sum(1 for status in statuses if status == "unhealthy")
        
        return {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                name: {
                    "status": result.status,
                    "message": result.message,
                    "duration_ms": result.duration_ms,
                    "details": result.details
                }
                for name, result in check_results.items()
            },
            "summary": {
                "total_checks": total_checks,
                "healthy": healthy_checks,
                "warning": warning_checks,
                "unhealthy": unhealthy_checks
            }
        }


class SystemMonitor:
    """Monitors system resources and performance."""
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics.
        
        Returns:
            SystemMetrics: Current system resource metrics
        """
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_used_mb = memory.used / 1024 / 1024
        memory_total_mb = memory.total / 1024 / 1024
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_used_gb = disk.used / 1024 / 1024 / 1024
        disk_total_gb = disk.total / 1024 / 1024 / 1024
        
        # Network usage (since boot)
        network = psutil.net_io_counters()
        network_sent_mb = network.bytes_sent / 1024 / 1024
        network_recv_mb = network.bytes_recv / 1024 / 1024
        
        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used_mb=memory_used_mb,
            memory_total_mb=memory_total_mb,
            disk_percent=disk.percent,
            disk_used_gb=disk_used_gb,
            disk_total_gb=disk_total_gb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb
        )


# Global instances
metrics_collector = MetricsCollector()
health_checker = HealthChecker()
system_monitor = SystemMonitor()


@asynccontextmanager
async def monitor_operation(operation_name: str):
    """Context manager to monitor operation performance.
    
    Args:
        operation_name: Name of the operation being monitored
        
    Yields:
        Dict with operation context
    """
    start_time = time.time()
    operation_logger = logging.getLogger(f"app.monitoring.{operation_name}")
    
    context = {
        "operation": operation_name,
        "start_time": start_time
    }
    
    try:
        operation_logger.info(f"Starting operation: {operation_name}")
        yield context
        
        duration_ms = (time.time() - start_time) * 1000
        operation_logger.info(
            f"Operation completed: {operation_name}",
            extra={
                "operation": operation_name,
                "duration_ms": duration_ms,
                "status": "success"
            }
        )
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        operation_logger.error(
            f"Operation failed: {operation_name} - {str(e)}",
            exc_info=True,
            extra={
                "operation": operation_name,
                "duration_ms": duration_ms,
                "status": "error",
                "error": str(e)
            }
        )
        raise


def get_monitoring_summary() -> Dict[str, Any]:
    """Get comprehensive monitoring summary.
    
    Returns:
        Dict[str, Any]: Complete monitoring data
    """
    system_metrics = system_monitor.get_system_metrics()
    app_metrics = metrics_collector.get_application_metrics()
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "cpu_percent": system_metrics.cpu_percent,
            "memory_percent": system_metrics.memory_percent,
            "memory_used_mb": system_metrics.memory_used_mb,
            "memory_total_mb": system_metrics.memory_total_mb,
            "disk_percent": system_metrics.disk_percent,
            "disk_used_gb": system_metrics.disk_used_gb,
            "disk_total_gb": system_metrics.disk_total_gb,
            "network_sent_mb": system_metrics.network_sent_mb,
            "network_recv_mb": system_metrics.network_recv_mb
        },
        "application": {
            "active_connections": app_metrics.active_connections,
            "request_count": app_metrics.request_count,
            "error_count": app_metrics.error_count,
            "error_rate": (
                app_metrics.error_count / app_metrics.request_count 
                if app_metrics.request_count > 0 else 0.0
            ),
            "avg_response_time_ms": app_metrics.avg_response_time_ms,
            "memory_usage_mb": app_metrics.memory_usage_mb,
            "uptime_seconds": app_metrics.uptime_seconds
        }
    }


# Export commonly used items
__all__ = [
    "HealthChecker",
    "MetricsCollector", 
    "SystemMonitor",
    "HealthStatus",
    "SystemMetrics",
    "ApplicationMetrics",
    "health_checker",
    "metrics_collector",
    "system_monitor",
    "monitor_operation",
    "get_monitoring_summary"
]