# syntax=docker/dockerfile:1
#
# Build the xESC OTP branding CLI (cmd/otp_brand) as a fully static linux/amd64
# binary. blst (BLS12-381) is a normal, pinned Go module dependency fetched via
# go.mod/go.sum — no manual library build, no /tmp paths, runtime CPU dispatch.
#
# The tool also #includes hwconf/.../xesc2_otp.h two directories up (to stay in
# sync with the firmware OTP layout), so the build CONTEXT must be the REPO ROOT:
#
#     docker build -f cmd/otp_brand/Dockerfile -o out .
#
# Result: ./out/otp_brand  (static binary; the final stage is scratch).
#
# Overridable: --build-arg GO_VERSION=1.24

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
# build-base = gcc + musl-dev: cgo compiles blst's C/asm sources and the
# xesc2_otp.h constants shim. musl makes the static link below clean.
RUN apk add --no-cache build-base

WORKDIR /src/cmd/otp_brand
# Fetch + verify modules first so this layer caches across source edits.
COPY cmd/otp_brand/go.mod cmd/otp_brand/go.sum ./
RUN go mod download

# Tool sources + the one firmware header the cgo include (-I../../hwconf/...)
# resolves to from /src/cmd/otp_brand.
COPY cmd/otp_brand/ ./
COPY hwconf/xtech/xesc_all_variants/xesc2_otp.h /src/hwconf/xtech/xesc_all_variants/xesc2_otp.h

# CGO + static link so the binary needs no libc at runtime (scratch-compatible).
RUN CGO_ENABLED=1 go build \
        -trimpath \
        -ldflags='-s -w -linkmode external -extldflags "-static"' \
        -o /otp_brand .

# Final stage: just the binary, so `docker build -o out .` exports out/otp_brand.
FROM scratch AS export
COPY --from=build /otp_brand /otp_brand
