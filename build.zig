const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .strip = true,
        .link_libc = true,
    });
    lib_mod.addCSourceFile(.{ .file = b.path("src/minisign_verify.c") });
    lib_mod.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    lib_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    lib_mod.linkSystemLibrary("sodium", .{});

    const lib = b.addLibrary(.{
        .name = "minisign_verify",
        .root_module = lib_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);
}
