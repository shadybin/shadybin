const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // What a dependent imports: b.dependency("shadybin", .{}).module("shadybin").
    const mod = b.addModule("shadybin", .{
        .root_source_file = b.path("src/shadybin.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run the SDK's tests and the shared conformance vectors").dependOn(&b.addRunArtifact(tests).step);
}
