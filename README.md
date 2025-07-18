# PlantPal - Your Plant Care Companion

A beautiful, responsive website for plant enthusiasts to discover, shop, and learn about plants.

## 🌱 Features

- **Plant Catalog**: Browse a curated collection of indoor and outdoor plants
- **Shopping Cart**: Add plants to cart and manage your purchases
- **Favorites**: Save your favorite plants for later
- **User Authentication**: Sign up, login, and manage your profile
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **Plant Care Tips**: Access helpful care information

## 🚀 Deployment

### Netlify Deployment

This project is configured for static site deployment on Netlify. The following files have been added to ensure proper deployment:

- `netlify.toml` - Netlify configuration
- `_redirects` - URL routing rules
- `index.html` - Landing page with automatic redirect
- `.gitignore` - Excludes sensitive files from deployment

### Deployment Steps

1. **Push to GitHub**: Ensure all files are committed and pushed to your GitHub repository
2. **Connect to Netlify**: 
   - Go to [Netlify](https://netlify.com)
   - Click "New site from Git"
   - Connect your GitHub repository
   - Deploy settings should be:
     - Build command: (leave empty)
     - Publish directory: `.`
3. **Environment Variables**: If you need backend functionality, you'll need to set up serverless functions or use a separate backend service

## 📁 Project Structure

```
├── dock.html              # Main landing page
├── login.html             # Login page
├── register.html          # Registration page
├── cart.html              # Shopping cart
├── favorites.html         # User favorites
├── profile.html           # User profile
├── forgot-password.html   # Password recovery
├── js/                    # JavaScript files
├── routes/                # Backend routes (for server deployment)
├── controllers/           # Backend controllers
├── models/                # Database models
├── middleware/            # Express middleware
├── utils/                 # Utility functions
├── netlify.toml           # Netlify configuration
├── _redirects             # URL routing
└── index.html             # Entry point with redirect
```

## 🔧 Local Development

To run this project locally:

1. **Static Site**: Simply open `index.html` in your browser
2. **With Backend**: 
   ```bash
   npm install
   npm start
   ```

## 🌐 Live Demo

Visit the deployed site at your Netlify URL once deployment is complete.

## 📝 Notes

- This is primarily a frontend application with static HTML files
- Backend functionality (authentication, database) requires a separate server deployment
- For full functionality, consider deploying the backend to services like:
  - Heroku
  - Railway
  - Render
  - DigitalOcean App Platform

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

This project is licensed under the MIT License. #   p l a n t p a l - w e b s i t e  
 #   p l a n t p a l - w e b s i t e  
 