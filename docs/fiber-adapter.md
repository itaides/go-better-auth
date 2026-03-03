# Fiber Integration Guide

This guide shows how to use go-better-auth with [Fiber](https://gofiber.io/), a fast HTTP framework for Go built on fasthttp.

## Quick Start

```bash
go get github.com/GoBetterAuth/go-better-auth/v2
```

```go
import fiberadapter "github.com/GoBetterAuth/go-better-auth/v2/adapters/fiber"

app := fiber.New()
app.Use("/api/auth", fiberadapter.New(fiberadapter.Config{
    Handler: auth.Handler(),
}))
```

See [examples/fiber/main.go](../examples/fiber/main.go) for a complete working example.

## Why a dedicated adapter?

Fiber uses [fasthttp](https://github.com/valyala/fasthttp), not Go's standard `net/http`. While Go provides `fasthttpadaptor` to bridge the two, it has a known issue: the request body can be lost for certain content types. This is critical for authentication endpoints that receive JSON payloads (sign-in, sign-up, password reset).

The Fiber adapter manually constructs `*http.Request` objects, ensuring:

- **Request body preservation** — Always reads the full body before constructing the request
- **Header propagation** — All request headers forwarded correctly
- **Multi-value response headers** — `Set-Cookie` headers (critical for sessions) use `Add()` not `Set()`
- **Query string preservation** — URL parameters passed through unchanged
- **Client IP forwarding** — `RemoteAddr` set from Fiber's context

## Skipping specific paths

Use the `Next` config to skip the adapter for certain paths:

```go
app.Use("/api/auth", fiberadapter.New(fiberadapter.Config{
    Handler: auth.Handler(),
    Next: func(c *fiber.Ctx) bool {
        // Skip for health check
        return c.Path() == "/api/auth/health"
    },
}))
```

## Custom error handling

Override the default error handler:

```go
app.Use("/api/auth", fiberadapter.New(fiberadapter.Config{
    Handler: auth.Handler(),
    ErrorHandler: func(c *fiber.Ctx, err error) error {
        log.Printf("adapter error: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "auth service error"})
    },
}))
```
