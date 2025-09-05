import type { Config } from "tailwindcss";

export default {
	darkMode: ["class"],
	content: [
		"./pages/**/*.{ts,tsx}",
		"./components/**/*.{ts,tsx}",
		"./app/**/*.{ts,tsx}",
		"./src/**/*.{ts,tsx}",
	],
	prefix: "",
	theme: {
		container: {
			center: true,
			padding: '2rem',
			screens: {
				'2xl': '1400px'
			}
		},
		extend: {
			colors: {
				border: 'hsl(var(--border))',
				input: 'hsl(var(--input))',
				ring: 'hsl(var(--ring))',
				background: 'hsl(var(--background))',
				foreground: 'hsl(var(--foreground))',
				primary: {
					DEFAULT: 'hsl(var(--primary))',
					foreground: 'hsl(var(--primary-foreground))',
					glow: 'hsl(var(--primary-glow))'
				},
				secondary: {
					DEFAULT: 'hsl(var(--secondary))',
					foreground: 'hsl(var(--secondary-foreground))'
				},
				destructive: {
					DEFAULT: 'hsl(var(--destructive))',
					foreground: 'hsl(var(--destructive-foreground))'
				},
				muted: {
					DEFAULT: 'hsl(var(--muted))',
					foreground: 'hsl(var(--muted-foreground))'
				},
				accent: {
					DEFAULT: 'hsl(var(--accent))',
					foreground: 'hsl(var(--accent-foreground))'
				},
				popover: {
					DEFAULT: 'hsl(var(--popover))',
					foreground: 'hsl(var(--popover-foreground))'
				},
				card: {
					DEFAULT: 'hsl(var(--card))',
					foreground: 'hsl(var(--card-foreground))'
				},
				glass: {
					background: 'hsl(var(--glass-background))',
					border: 'hsl(var(--glass-border))'
				},
				severity: {
					low: 'hsl(var(--severity-low))',
					'low-glow': 'hsl(var(--severity-low-glow))',
					medium: 'hsl(var(--severity-medium))',
					'medium-glow': 'hsl(var(--severity-medium-glow))',
					high: 'hsl(var(--severity-high))',
					'high-glow': 'hsl(var(--severity-high-glow))',
					critical: 'hsl(var(--severity-critical))',
					'critical-glow': 'hsl(var(--severity-critical-glow))'
				}
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 2px)',
				sm: 'calc(var(--radius) - 4px)'
			},
			backdropBlur: {
				'glass': '16px'
			},
			boxShadow: {
				'glow': 'var(--shadow-glow)',
				'depth': 'var(--shadow-depth)',
				'glass': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
			},
			backgroundImage: {
				'gradient-cosmic': 'var(--gradient-cosmic)',
				'gradient-glass': 'var(--gradient-glass)',
				'gradient-primary': 'var(--gradient-primary)',
				'gradient-severity-low': 'var(--gradient-severity-low)',
				'gradient-severity-medium': 'var(--gradient-severity-medium)',
				'gradient-severity-high': 'var(--gradient-severity-high)'
			},
			keyframes: {
				'accordion-down': {
					from: { height: '0', opacity: '0' },
					to: { height: 'var(--radix-accordion-content-height)', opacity: '1' }
				},
				'accordion-up': {
					from: { height: 'var(--radix-accordion-content-height)', opacity: '1' },
					to: { height: '0', opacity: '0' }
				},
				'orbit-rotate': {
					'0%': { transform: 'rotateY(0deg)' },
					'100%': { transform: 'rotateY(360deg)' }
				},
				'float': {
					'0%, 100%': { transform: 'translateY(0px)' },
					'50%': { transform: 'translateY(-10px)' }
				},
				'glow-pulse': {
					'0%, 100%': { opacity: '0.5', transform: 'scale(1)' },
					'50%': { opacity: '1', transform: 'scale(1.05)' }
				},
				'card-enter': {
					'0%': { opacity: '0', transform: 'translateZ(-100px) rotateY(90deg)' },
					'100%': { opacity: '1', transform: 'translateZ(0px) rotateY(0deg)' }
				},
				'focus-zoom': {
					'0%': { transform: 'scale(1) translateZ(0px)' },
					'100%': { transform: 'scale(1.2) translateZ(100px)' }
				}
			},
			animation: {
				'accordion-down': 'accordion-down 0.3s ease-out',
				'accordion-up': 'accordion-up 0.3s ease-out',
				'orbit-rotate': 'orbit-rotate 120s linear infinite',
				'float': 'float 6s ease-in-out infinite',
				'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
				'card-enter': 'card-enter 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
				'focus-zoom': 'focus-zoom 0.5s cubic-bezier(0.4, 0, 0.2, 1)'
			}
		}
	},
	plugins: [require("tailwindcss-animate")],
} satisfies Config;
