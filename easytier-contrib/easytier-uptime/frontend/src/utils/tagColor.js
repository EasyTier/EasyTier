// Deterministic tag color generator (pure frontend)
// Same tag => same color; different tags => different colors

function stringHash(str) {
  const s = String(str)
  let hash = 5381
  for (let i = 0; i < s.length; i++) {
    hash = (hash * 33) ^ s.charCodeAt(i)
  }
  return hash >>> 0 // ensure positive
}

function hslToRgb(h, s, l) {
  // h,s,l in [0,1]
  let r, g, b

  if (s === 0) {
    r = g = b = l // achromatic
  } else {
    const hue2rgb = (p, q, t) => {
      if (t < 0) t += 1
      if (t > 1) t -= 1
      if (t < 1 / 6) return p + (q - p) * 6 * t
      if (t < 1 / 2) return q
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6
      return p
    }

    const q = l < 0.5 ? l * (1 + s) : l + s - l * s
    const p = 2 * l - q
    r = hue2rgb(p, q, h + 1 / 3)
    g = hue2rgb(p, q, h)
    b = hue2rgb(p, q, h - 1 / 3)
  }

  return [Math.round(r * 255), Math.round(g * 255), Math.round(b * 255)]
}

function rgbToHex(r, g, b) {
  const toHex = (v) => v.toString(16).padStart(2, '0')
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`
}

export function getTagStyle(tag) {
  const hash = stringHash(tag)
  const hue = hash % 360 // 0-359
  const saturation = 65 // percentage
  const lightness = 47 // percentage

  const rgb = hslToRgb(hue / 360, saturation / 100, lightness / 100)
  const hex = rgbToHex(rgb[0], rgb[1], rgb[2])

  // Perceived brightness for text color selection
  const brightness = rgb[0] * 0.299 + rgb[1] * 0.587 + rgb[2] * 0.114
  const textColor = brightness > 160 ? '#1f1f1f' : '#ffffff'

  return {
    backgroundColor: hex,
    borderColor: hex,
    color: textColor
  }
}