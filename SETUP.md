# Project Setup Guide

Follow these steps to set up the VI Backend project locally.

## Prerequisites
- **Node.js**: v18 or higher
- **PostgreSQL**: Local or remote instance
- **npm**: v9 or higher

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd VI_Backend
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

## Environment Configuration

The project uses separate environment files for development and production. `cross-env` is used to load the correct file based on the script you run.

1.  **Create your environment files:**
    Copy `.env.example` to create `.env.development` and `.env.production`.

    ```bash
    cp .env.example .env.development
    cp .env.example .env.production
    ```

2.  **Configure `.env.development`:**
    ```env
    PORT=3000
    DATABASE_URL="postgresql://user:password@localhost:5432/vi_backend_dev"
    ```

3.  **Configure `.env.production`:**
    ```env
    PORT=9000
    DATABASE_URL="postgresql://user:password@localhost:5432/vi_backend_prod"
    ```

## Database Setup

1.  **Initialize the database (Development):**
    This command pushes the schema to the database defined in `.env.development`.

    ```bash
    npx prisma migrate dev --name init
    ```

2.  **Generate Prisma Client:**
    ```bash
    npx prisma generate
    ```

## Running the Application

### Development
Runs the server on `http://localhost:3000` with hot-reloading (nodemon). Uses `.env.development`.

```bash
npm run dev
```

### Production
Runs the server on `http://localhost:9000`. Uses `.env.production`.

```bash
npm start
```

## Project Structure

The project follows a **Modular MVC Architecture**:

```
src/
├── modules/            # Feature modules
│   └── health/         # Example feature
│       ├── health.controller.js
│       └── health.routes.js
├── routes/             # Main application router
├── middlewares/        # Global middlewares
├── utils/              # Global utilities (logger, etc.)
└── server.js           # Entry point
```

## Commands Cheatsheet

| Command | Description |
| :--- | :--- |
| `npm run dev` | Start dev server (nodemon, .env.development) |
| `npm start` | Start production server (node, .env.production) |
| `npm run lint` | Run ESLint |
| `npm run format` | Format code with Prettier |
| `npx prisma studio` | Open database GUI |
