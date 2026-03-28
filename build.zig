const std = @import("std");

const include_paths: []const []const u8 = &.{
    ".",
    "src",
    "include",
    "quakey/include",
};

const files: []const []const u8 = &.{

    "src/chunk_store.c",
    "src/client.c",
    "src/client_table.c",
    "src/http_proxy.c",
    "src/invariant_checker.c",
    "src/log.c",
    "src/main.c",
    "src/metadata.c",
    "src/random_client.c",
    "src/server.c",

    "lib/basic.c",
    "lib/byte_queue.c",
    "lib/file_system.c",
    "lib/http_parse.c",
    "lib/http_server.c",
    "lib/message.c",
    "lib/tcp.c",
    "lib/tls_openssl.c",
    "lib/tls_schannel.c",

    "quakey/src/mockfs.c",
    "quakey/src/quakey.c",
};

fn buildTarget(b: *std.Build, name: []const u8, macros: []const []const u8, flags: []const []const u8) void {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .target = b.graph.host,
        }),
    });
    for (macros) |m| {
        exe.root_module.addCMacro(m, "");
    }
    for (include_paths) |p| {
        exe.root_module.addIncludePath(b.path(p));
    }
    exe.root_module.addCSourceFiles(.{ .files = files, .flags = flags });
    exe.root_module.link_libc = true;

    b.installArtifact(exe);
}

pub fn build(b: *std.Build) !void {

    // Server
    buildTarget(b,
        "toasty",
        &.{ "MAIN_SERVER" },
        &.{ "-Wall", "-Wextra", "-ggdb", "-O0" },
    );

    // Client
    buildTarget(b,
        "toasty_random_client",
        &.{ "MAIN_CLIENT" },
        &.{ "-Wall", "-Wextra", "-ggdb", "-O0" },
    );

    // Proxy
    buildTarget(b,
        "toasty_proxy",
        &.{ "MAIN_HTTP_PROXY" },
        &.{ "-Wall", "-Wextra", "-ggdb", "-O0" },
    );

    // Simulation
    buildTarget(b,
        "toasty_simulation",
        &.{ "MAIN_SIMULATION", "FAULT_INJECTION" },
        &.{ "-Wall", "-Wextra", "-ggdb", "-O0" },
    );
}
