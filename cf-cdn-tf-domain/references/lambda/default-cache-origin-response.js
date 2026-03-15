// Lambda@Edge origin-response: Cloudflare default cache behavior
// Injects Cache-Control header for cacheable file extensions when origin
// does not provide one. Replicates Cloudflare's implicit caching behavior:
// - ~70 file extensions + robots.txt are cacheable
// - Default TTL: 2 hours (only when origin has no Cache-Control header)
// - If origin returns Cache-Control, it is respected (not overridden)
//
// TEMPLATE USAGE:
// - tf-domain copies this file as-is when no custom TTL overrides exist
// - When custom TTL overrides exist (>20 extensions), tf-domain replaces
//   the CUSTOM_TTL_PLACEHOLDER block with a customTtl map and changes
//   the ttl assignment to: const ttl = customTtl[extension] || 7200;

exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const request = event.Records[0].cf.request;

    // Skip if origin already provided Cache-Control
    if (response.headers['cache-control']) {
        callback(null, response);
        return;
    }

    const cacheableExtensions = new Set([
        '7z', 'csv', 'gif', 'midi', 'png', 'tif', 'zip',
        'avi', 'doc', 'gz', 'mkv', 'ppt', 'tiff', 'zst',
        'avif', 'docx', 'ico', 'mp3', 'pptx', 'ttf',
        'apk', 'dmg', 'iso', 'mp4', 'ps', 'webm',
        'bin', 'ejs', 'jar', 'ogg', 'rar', 'webp',
        'bmp', 'eot', 'jpg', 'otf', 'svg', 'woff',
        'bz2', 'eps', 'jpeg', 'pdf', 'svgz', 'woff2',
        'class', 'exe', 'js', 'pict', 'swf', 'xls',
        'css', 'flac', 'mid', 'pls', 'tar', 'xlsx'
    ]);

    const uri = request.uri.toLowerCase();
    const dotPos = uri.lastIndexOf('.');
    const extension = dotPos !== -1 ? uri.substring(dotPos + 1) : '';

    if (cacheableExtensions.has(extension) || uri.endsWith('/robots.txt')) {
        // CUSTOM_TTL_PLACEHOLDER: tf-domain inserts custom TTL map here when needed
        // Example replacement for >20 custom-TTL extensions:
        //   const customTtl = {"apk": 31536000, "iso": 604800};
        //   const ttl = customTtl[extension] || 7200;

        const ttl = 7200;
        response.headers['cache-control'] = [{
            key: 'Cache-Control',
            value: 'public, max-age=' + ttl
        }];
    }

    callback(null, response);
};
