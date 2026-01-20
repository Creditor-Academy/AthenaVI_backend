const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const errorHandler = require('./middlewares/errorHandler');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.get("/", (req, res) => {
  res.send("Virtual Instructor Backend Running ");
});

const userRoutes = require("./modules/user/user.routes");
app.use("/api/user", userRoutes);

app.use(errorHandler);

module.exports = app;
