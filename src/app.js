const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const errorHandler = require('./middlewares/errorHandler');
const { connectRedis } = require("./shared/config/redis");
const { createCorsMiddleware, logCorsConfig } = require('./shared/config/cors');
const cookieParser = require('cookie-parser')

const app = express();

const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS);
if (Number.isFinite(trustProxyHops) && trustProxyHops >= 0) {
  app.set('trust proxy', trustProxyHops);
} else if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

logCorsConfig();

(async () => {
  try {
    await connectRedis();
    console.log("All services connected");
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
})();

app.use(createCorsMiddleware());
app.use(helmet());
/** Base64 voice clone payloads exceed Express's default (~100kb). Override with JSON_BODY_LIMIT (e.g. 32mb). */
const jsonBodyLimit =
  (process.env.JSON_BODY_LIMIT && String(process.env.JSON_BODY_LIMIT).trim()) || '32mb';
app.use(express.json({ limit: jsonBodyLimit }));
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send('Virtual Instructor Backend Running ');
});

const userRoutes = require('./modules/user/user.routes');
const authRoutes = require('./modules/auth/auth.routes');
const workspaceRoutes = require('./modules/workspace/workspace.routes');
const creditRoutes = require('./modules/credit/credit.routes');
const assetRoutes = require('./modules/asset/asset.routes');
const heygenRoutes = require('./modules/heygen/heygen.routes');
const superadminRoutes = require('./modules/superadmin/superadmin.routes');
const stockRoutes = require('./modules/stock/stock.routes');

app.use('/api/user', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/workspaces', workspaceRoutes);
app.use('/api/credits', creditRoutes);
app.use("/api/assets", assetRoutes);
app.use('/api/heygen', heygenRoutes);
app.use('/api/stock', stockRoutes);
app.use('/api/superadmin', superadminRoutes);
app.use(errorHandler);

module.exports = app;
