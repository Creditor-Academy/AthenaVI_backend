const express = require('express');
const Joi = require('joi');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const asyncHandler = require('../../shared/utils/asyncHandler');
const { fetchProxiedImage } = require('./mediaProxy.service');

const router = express.Router();

const imageProxySchema = Joi.object({
  query: Joi.object({
    url: Joi.string().trim().uri({ scheme: ['https'] }).max(4096).required(),
  }),
});

/**
 * GET /api/media/image?url=<one of our image URLs>
 * The image itself (not JSON), from our origin, so an in-browser export can draw it.
 * See mediaProxy.service.js for what it will and won't fetch.
 */
router.get(
  '/image',
  authMiddleware,
  validate(imageProxySchema),
  asyncHandler(async (req, res) => {
    const { body, contentType } = await fetchProxiedImage(req.query.url);
    res.set({
      'Content-Type': contentType,
      'Content-Length': String(body.length),
      'Cache-Control': 'private, max-age=300',
      'X-Content-Type-Options': 'nosniff',
      // Shown as an image only; never run as a page (SVG can hold scripts).
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    });
    res.status(200).send(body);
  })
);

module.exports = router;
