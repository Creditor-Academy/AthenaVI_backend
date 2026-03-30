const axios = require('axios');

const HEYGEN_API_KEY = process.env.HEYGEN_API_KEY;

const getVoiceList=  async() => {    
    const response = await axios.get(
      "https://api.heygen.com/v2/voices", // confirm endpoint
      {
        headers: {
          "X-Api-Key": HEYGEN_API_KEY,
        },
      }
    );
    
    return response.data.data.voices
  }

  module.exports = {
    getVoiceList
  }