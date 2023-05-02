const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib = b.addStaticLibrary(.{
        .name = "minisign_verify",
        .root_source_file = .{ .path = "src/minisign_verify.c" },
        .target = target,
        .optimize = optimize,
    });
    lib.addIncludePath("/opt/homebrew/include");
    lib.addSystemIncludePath("/opt/homebrew/lib");
    lib.linkSystemLibrary("sodium");
    b.installArtifact(lib);
}
