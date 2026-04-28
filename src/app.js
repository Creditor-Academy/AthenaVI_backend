const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const errorHandler = require('./middlewares/errorHandler');
const { connectRedis } = require("./shared/config/redis");
const cookieParser = require('cookie-parser')

const app = express();
(async () => {
  try {
    await connectRedis();
    console.log("All services connected");
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
})();

app.use(helmet());
app.use(cors());
app.use(express.json());
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

app.use('/api/user', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/workspaces', workspaceRoutes);
app.use('/api/credits', creditRoutes);
app.use("/api/assets", assetRoutes);
app.use('/api/heygen', heygenRoutes);

app.use(errorHandler);

module.exports = app;
