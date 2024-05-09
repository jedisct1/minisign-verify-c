const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib = b.addStaticLibrary(.{
        .name = "minisign_verify",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    lib.addCSourceFile(.{ .file = b.path("src/minisign_verify.c") });
    lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    lib.linkSystemLibrary("sodium");
    b.installArtifact(lib);
}
