--e3fd26ccb53089de73f1bd3605778f2c09912ede71c6ea95824521ec0289
Content-Disposition: form-data; name="snippet.js"; filename="snippet.js"
Content-Type: application/javascript+module

export default {
  async fetch(request) {
    return new Response(null, {
      status: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      },
    });
  },
};

--e3fd26ccb53089de73f1bd3605778f2c09912ede71c6ea95824521ec0289--
