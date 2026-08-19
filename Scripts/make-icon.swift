#!/usr/bin/env swift
// Renders the HDWatcher app icon at every size macOS asks for.
// A dark disk platter with a watching aperture and activity arcs.

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

func drawIcon(size: CGFloat) -> CGImage? {
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(data: nil, width: Int(size), height: Int(size),
                              bitsPerComponent: 8, bytesPerRow: 0,
                              space: colorSpace,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return nil }

    let s = size
    // macOS icons sit inside a margin rather than filling the canvas.
    let inset = s * 0.055
    let rect = CGRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    let corner = rect.width * 0.2237   // matches the macOS squircle proportion

    // Background gradient
    let bg = CGPath(roundedRect: rect, cornerWidth: corner, cornerHeight: corner, transform: nil)
    ctx.saveGState()
    ctx.addPath(bg)
    ctx.clip()
    let colors = [
        CGColor(red: 0.08, green: 0.11, blue: 0.24, alpha: 1),
        CGColor(red: 0.16, green: 0.20, blue: 0.45, alpha: 1),
        CGColor(red: 0.31, green: 0.18, blue: 0.52, alpha: 1),
    ] as CFArray
    if let gradient = CGGradient(colorsSpace: colorSpace, colors: colors,
                                 locations: [0, 0.55, 1]) {
        ctx.drawLinearGradient(gradient,
                               start: CGPoint(x: rect.minX, y: rect.maxY),
                               end: CGPoint(x: rect.maxX, y: rect.minY),
                               options: [])
    }

    let center = CGPoint(x: rect.midX, y: rect.midY)

    // Activity arcs radiating from the platter.
    let arcColors = [
        CGColor(red: 0.20, green: 0.85, blue: 0.95, alpha: 0.85),
        CGColor(red: 0.35, green: 0.72, blue: 1.00, alpha: 0.55),
        CGColor(red: 1.00, green: 0.62, blue: 0.25, alpha: 0.40),
    ]
    for (index, color) in arcColors.enumerated() {
        let radius = rect.width * (0.30 + CGFloat(index) * 0.085)
        ctx.setStrokeColor(color)
        ctx.setLineWidth(max(1, s * 0.016))
        ctx.setLineCap(.round)
        ctx.addArc(center: center, radius: radius,
                   startAngle: .pi * 0.15, endAngle: .pi * 0.85, clockwise: false)
        ctx.strokePath()
        ctx.addArc(center: center, radius: radius,
                   startAngle: .pi * 1.15, endAngle: .pi * 1.85, clockwise: false)
        ctx.strokePath()
    }

    // Disk platter
    let platterRadius = rect.width * 0.235
    ctx.setFillColor(CGColor(red: 0.93, green: 0.95, blue: 1.0, alpha: 1))
    ctx.addArc(center: center, radius: platterRadius, startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.fillPath()

    // Aperture ring — the "watching" element
    ctx.setStrokeColor(CGColor(red: 0.10, green: 0.13, blue: 0.28, alpha: 1))
    ctx.setLineWidth(max(1, s * 0.022))
    ctx.addArc(center: center, radius: platterRadius * 0.60, startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.strokePath()

    // Spindle
    ctx.setFillColor(CGColor(red: 0.13, green: 0.17, blue: 0.35, alpha: 1))
    ctx.addArc(center: center, radius: platterRadius * 0.20, startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.fillPath()

    // Highlight sweep across the platter
    ctx.saveGState()
    ctx.addArc(center: center, radius: platterRadius, startAngle: 0, endAngle: .pi * 2, clockwise: false)
    ctx.clip()
    ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.55))
    ctx.fill(CGRect(x: center.x - platterRadius, y: center.y,
                    width: platterRadius * 2, height: platterRadius))
    ctx.restoreGState()

    ctx.restoreGState()
    return ctx.makeImage()
}

let outputDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
let iconset = URL(fileURLWithPath: outputDir).appendingPathComponent("AppIcon.iconset")
try? FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

let variants: [(name: String, size: CGFloat)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]

for variant in variants {
    guard let image = drawIcon(size: variant.size) else {
        FileHandle.standardError.write("failed to render \(variant.name)\n".data(using: .utf8)!)
        exit(1)
    }
    let url = iconset.appendingPathComponent("\(variant.name).png")
    guard let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else {
        exit(1)
    }
    CGImageDestinationAddImage(dest, image, nil)
    CGImageDestinationFinalize(dest)
}
print("wrote \(variants.count) icon variants to \(iconset.path)")
