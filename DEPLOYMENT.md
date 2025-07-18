# Netlify Deployment Guide

## Quick Setup

1. **Repository Structure**: This is a static HTML site with no build process required
2. **Netlify Settings**:
   - Build command: (leave empty)
   - Publish directory: `.`
   - Node version: (not needed for static sites)

## Configuration Files

- `netlify.toml`: Minimal configuration for static site deployment
- `_redirects`: Simple routing for SPA-like behavior
- `index.html`: Entry point that redirects to main page
- `.gitignore`: Excludes unnecessary files from deployment

## Troubleshooting

If you encounter "Base directory does not exist" error:

1. Ensure all configuration files are committed to the repository
2. Verify the `netlify.toml` file is in the root directory
3. Check that the publish directory is set to `.` (current directory)
4. Make sure there are no syntax errors in configuration files

## Static Site Notes

- No build process required
- All HTML files are served directly
- Backend functionality requires separate deployment
- Frontend works completely as static files 