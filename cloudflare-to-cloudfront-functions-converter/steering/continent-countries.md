# Country to Continent Mapping

Latest GeoIP country codes (ISO 3166-1 alpha-2) mapped to continents, as of 2025.

## Continent Codes

- **AS** - Asia
- **EU** - Europe  
- **AF** - Africa
- **NA** - North America
- **SA** - South America
- **OC** - Oceania
- **AN** - Antarctica

## Asia (AS)

```
AF, AM, AZ, BH, BD, BT, BN, KH, CN, CX, CC, CY, GE, HK, IN, 
ID, IR, IQ, IL, JP, JO, KZ, KP, KR, KW, KG, LA, LB, MO, MY, 
MV, MN, MM, NP, OM, PK, PS, PH, QA, SA, SG, LK, SY, TW, TJ, 
TH, TL, TR, TM, AE, UZ, VN, YE
```

**Total**: 53 countries

## Europe (EU)

```
AL, AD, AT, BY, BE, BA, BG, HR, CZ, DK, EE, FO, FI, FR, DE, 
GI, GR, GG, HU, IS, IE, IM, IT, JE, LV, LI, LT, LU, MT, MD, 
MC, ME, NL, MK, NO, PL, PT, RO, RU, SM, RS, SK, SI, ES, SJ, 
SE, CH, UA, GB, VA, AX
```

**Total**: 50 countries/territories

## Africa (AF)

```
DZ, AO, BJ, BW, BF, BI, CV, CM, CF, TD, KM, CD, CG, CI, DJ, 
EG, GQ, ER, SZ, ET, GA, GM, GH, GN, GW, KE, LS, LR, LY, MG, 
MW, ML, MR, MU, YT, MA, MZ, NA, NE, NG, RE, RW, ST, SN, SC, 
SL, SO, ZA, SS, SD, TZ, TG, TN, UG, EH, ZM, ZW
```

**Total**: 56 countries/territories

## North America (NA)

```
AG, BS, BB, BZ, BM, VG, CA, KY, CR, CU, CW, DM, DO, SV, GL, 
GD, GP, GT, HT, HN, JM, MQ, MX, MS, NI, PA, PR, KN, LC, PM, 
VC, SX, TT, TC, US, VI
```

**Total**: 36 countries/territories

## South America (SA)

```
AR, BO, BR, CL, CO, EC, FK, GF, GY, PY, PE, SR, UY, VE
```

**Total**: 14 countries/territories

## Oceania (OC)

```
AS, AU, CK, FJ, PF, GU, KI, MH, FM, NR, NC, NZ, NU, NF, MP, 
PW, PG, PN, WS, SB, TK, TO, TV, VU, WF
```

**Total**: 25 countries/territories

## Antarctica (AN)

```
AQ, BV, TF, HM, GS
```

**Total**: 5 territories

## Usage in CloudFront Functions

**Strategy: Always use KVS**

Store country-to-continent mapping in KVS to reduce function size. Use prefix `continent:` for keys.

**CloudFront Function:**
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            // Example: Redirect Asia users to Asia-specific page
            if (continent === 'AS' && uri === '/welcome') {
                return {
                    statusCode: 302,
                    headers: {
                        'location': { value: '/asia/welcome' }
                    }
                };
            }
        } catch (err) {
            // Country not in mapping, continue with default behavior
        }
    }
    
    return request;
}
```

**KVS JSON** (with prefix `continent:`):
```json
{
  "data": [
    {"key": "continent:AF", "value": "AS"},
    {"key": "continent:AM", "value": "AS"},
    {"key": "continent:AZ", "value": "AS"},
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CA", "value": "NA"},
    {"key": "continent:GB", "value": "EU"},
    {"key": "continent:DE", "value": "EU"}
  ]
}
```

**CloudFront Function**:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            // Example: Redirect Asia users to Asia-specific page
            if (continent === 'AS' && uri === '/welcome') {
                return {
                    statusCode: 302,
                    headers: {
                        'location': { value: '/asia/welcome' }
                    }
                };
            }
        } catch (err) {
            // Country not in mapping, continue with default behavior
        }
    }
    
    return request;
}
```

## Complete KVS Data

For reference, here's the complete mapping for all 239 countries/territories:

### Asia (AS) - 53 entries
```json
{"key": "continent:AF", "value": "AS"},
{"key": "continent:AM", "value": "AS"},
{"key": "continent:AZ", "value": "AS"},
{"key": "continent:BH", "value": "AS"},
{"key": "continent:BD", "value": "AS"},
{"key": "continent:BT", "value": "AS"},
{"key": "continent:BN", "value": "AS"},
{"key": "continent:KH", "value": "AS"},
{"key": "continent:CN", "value": "AS"},
{"key": "continent:CX", "value": "AS"},
{"key": "continent:CC", "value": "AS"},
{"key": "continent:CY", "value": "AS"},
{"key": "continent:GE", "value": "AS"},
{"key": "continent:HK", "value": "AS"},
{"key": "continent:IN", "value": "AS"},
{"key": "continent:ID", "value": "AS"},
{"key": "continent:IR", "value": "AS"},
{"key": "continent:IQ", "value": "AS"},
{"key": "continent:IL", "value": "AS"},
{"key": "continent:JP", "value": "AS"},
{"key": "continent:JO", "value": "AS"},
{"key": "continent:KZ", "value": "AS"},
{"key": "continent:KP", "value": "AS"},
{"key": "continent:KR", "value": "AS"},
{"key": "continent:KW", "value": "AS"},
{"key": "continent:KG", "value": "AS"},
{"key": "continent:LA", "value": "AS"},
{"key": "continent:LB", "value": "AS"},
{"key": "continent:MO", "value": "AS"},
{"key": "continent:MY", "value": "AS"},
{"key": "continent:MV", "value": "AS"},
{"key": "continent:MN", "value": "AS"},
{"key": "continent:MM", "value": "AS"},
{"key": "continent:NP", "value": "AS"},
{"key": "continent:OM", "value": "AS"},
{"key": "continent:PK", "value": "AS"},
{"key": "continent:PS", "value": "AS"},
{"key": "continent:PH", "value": "AS"},
{"key": "continent:QA", "value": "AS"},
{"key": "continent:SA", "value": "AS"},
{"key": "continent:SG", "value": "AS"},
{"key": "continent:LK", "value": "AS"},
{"key": "continent:SY", "value": "AS"},
{"key": "continent:TW", "value": "AS"},
{"key": "continent:TJ", "value": "AS"},
{"key": "continent:TH", "value": "AS"},
{"key": "continent:TL", "value": "AS"},
{"key": "continent:TR", "value": "AS"},
{"key": "continent:TM", "value": "AS"},
{"key": "continent:AE", "value": "AS"},
{"key": "continent:UZ", "value": "AS"},
{"key": "continent:VN", "value": "AS"},
{"key": "continent:YE", "value": "AS"}
```

### Europe (EU) - 50 entries
```json
{"key": "continent:AL", "value": "EU"},
{"key": "continent:AD", "value": "EU"},
{"key": "continent:AT", "value": "EU"},
{"key": "continent:BY", "value": "EU"},
{"key": "continent:BE", "value": "EU"},
{"key": "continent:BA", "value": "EU"},
{"key": "continent:BG", "value": "EU"},
{"key": "continent:HR", "value": "EU"},
{"key": "continent:CZ", "value": "EU"},
{"key": "continent:DK", "value": "EU"},
{"key": "continent:EE", "value": "EU"},
{"key": "continent:FO", "value": "EU"},
{"key": "continent:FI", "value": "EU"},
{"key": "continent:FR", "value": "EU"},
{"key": "continent:DE", "value": "EU"},
{"key": "continent:GI", "value": "EU"},
{"key": "continent:GR", "value": "EU"},
{"key": "continent:GG", "value": "EU"},
{"key": "continent:HU", "value": "EU"},
{"key": "continent:IS", "value": "EU"},
{"key": "continent:IE", "value": "EU"},
{"key": "continent:IM", "value": "EU"},
{"key": "continent:IT", "value": "EU"},
{"key": "continent:JE", "value": "EU"},
{"key": "continent:LV", "value": "EU"},
{"key": "continent:LI", "value": "EU"},
{"key": "continent:LT", "value": "EU"},
{"key": "continent:LU", "value": "EU"},
{"key": "continent:MT", "value": "EU"},
{"key": "continent:MD", "value": "EU"},
{"key": "continent:MC", "value": "EU"},
{"key": "continent:ME", "value": "EU"},
{"key": "continent:NL", "value": "EU"},
{"key": "continent:MK", "value": "EU"},
{"key": "continent:NO", "value": "EU"},
{"key": "continent:PL", "value": "EU"},
{"key": "continent:PT", "value": "EU"},
{"key": "continent:RO", "value": "EU"},
{"key": "continent:RU", "value": "EU"},
{"key": "continent:SM", "value": "EU"},
{"key": "continent:RS", "value": "EU"},
{"key": "continent:SK", "value": "EU"},
{"key": "continent:SI", "value": "EU"},
{"key": "continent:ES", "value": "EU"},
{"key": "continent:SJ", "value": "EU"},
{"key": "continent:SE", "value": "EU"},
{"key": "continent:CH", "value": "EU"},
{"key": "continent:UA", "value": "EU"},
{"key": "continent:GB", "value": "EU"},
{"key": "continent:VA", "value": "EU"},
{"key": "continent:AX", "value": "EU"}
```

### Africa (AF) - 56 entries
```json
{"key": "continent:DZ", "value": "AF"},
{"key": "continent:AO", "value": "AF"},
{"key": "continent:BJ", "value": "AF"},
{"key": "continent:BW", "value": "AF"},
{"key": "continent:BF", "value": "AF"},
{"key": "continent:BI", "value": "AF"},
{"key": "continent:CV", "value": "AF"},
{"key": "continent:CM", "value": "AF"},
{"key": "continent:CF", "value": "AF"},
{"key": "continent:TD", "value": "AF"},
{"key": "continent:KM", "value": "AF"},
{"key": "continent:CD", "value": "AF"},
{"key": "continent:CG", "value": "AF"},
{"key": "continent:CI", "value": "AF"},
{"key": "continent:DJ", "value": "AF"},
{"key": "continent:EG", "value": "AF"},
{"key": "continent:GQ", "value": "AF"},
{"key": "continent:ER", "value": "AF"},
{"key": "continent:SZ", "value": "AF"},
{"key": "continent:ET", "value": "AF"},
{"key": "continent:GA", "value": "AF"},
{"key": "continent:GM", "value": "AF"},
{"key": "continent:GH", "value": "AF"},
{"key": "continent:GN", "value": "AF"},
{"key": "continent:GW", "value": "AF"},
{"key": "continent:KE", "value": "AF"},
{"key": "continent:LS", "value": "AF"},
{"key": "continent:LR", "value": "AF"},
{"key": "continent:LY", "value": "AF"},
{"key": "continent:MG", "value": "AF"},
{"key": "continent:MW", "value": "AF"},
{"key": "continent:ML", "value": "AF"},
{"key": "continent:MR", "value": "AF"},
{"key": "continent:MU", "value": "AF"},
{"key": "continent:YT", "value": "AF"},
{"key": "continent:MA", "value": "AF"},
{"key": "continent:MZ", "value": "AF"},
{"key": "continent:NA", "value": "AF"},
{"key": "continent:NE", "value": "AF"},
{"key": "continent:NG", "value": "AF"},
{"key": "continent:RE", "value": "AF"},
{"key": "continent:RW", "value": "AF"},
{"key": "continent:ST", "value": "AF"},
{"key": "continent:SN", "value": "AF"},
{"key": "continent:SC", "value": "AF"},
{"key": "continent:SL", "value": "AF"},
{"key": "continent:SO", "value": "AF"},
{"key": "continent:ZA", "value": "AF"},
{"key": "continent:SS", "value": "AF"},
{"key": "continent:SD", "value": "AF"},
{"key": "continent:TZ", "value": "AF"},
{"key": "continent:TG", "value": "AF"},
{"key": "continent:TN", "value": "AF"},
{"key": "continent:UG", "value": "AF"},
{"key": "continent:EH", "value": "AF"},
{"key": "continent:ZM", "value": "AF"},
{"key": "continent:ZW", "value": "AF"}
```

### North America (NA) - 36 entries
```json
{"key": "continent:AG", "value": "NA"},
{"key": "continent:BS", "value": "NA"},
{"key": "continent:BB", "value": "NA"},
{"key": "continent:BZ", "value": "NA"},
{"key": "continent:BM", "value": "NA"},
{"key": "continent:VG", "value": "NA"},
{"key": "continent:CA", "value": "NA"},
{"key": "continent:KY", "value": "NA"},
{"key": "continent:CR", "value": "NA"},
{"key": "continent:CU", "value": "NA"},
{"key": "continent:CW", "value": "NA"},
{"key": "continent:DM", "value": "NA"},
{"key": "continent:DO", "value": "NA"},
{"key": "continent:SV", "value": "NA"},
{"key": "continent:GL", "value": "NA"},
{"key": "continent:GD", "value": "NA"},
{"key": "continent:GP", "value": "NA"},
{"key": "continent:GT", "value": "NA"},
{"key": "continent:HT", "value": "NA"},
{"key": "continent:HN", "value": "NA"},
{"key": "continent:JM", "value": "NA"},
{"key": "continent:MQ", "value": "NA"},
{"key": "continent:MX", "value": "NA"},
{"key": "continent:MS", "value": "NA"},
{"key": "continent:NI", "value": "NA"},
{"key": "continent:PA", "value": "NA"},
{"key": "continent:PR", "value": "NA"},
{"key": "continent:KN", "value": "NA"},
{"key": "continent:LC", "value": "NA"},
{"key": "continent:PM", "value": "NA"},
{"key": "continent:VC", "value": "NA"},
{"key": "continent:SX", "value": "NA"},
{"key": "continent:TT", "value": "NA"},
{"key": "continent:TC", "value": "NA"},
{"key": "continent:US", "value": "NA"},
{"key": "continent:VI", "value": "NA"}
```

### South America (SA) - 14 entries
```json
{"key": "continent:AR", "value": "SA"},
{"key": "continent:BO", "value": "SA"},
{"key": "continent:BR", "value": "SA"},
{"key": "continent:CL", "value": "SA"},
{"key": "continent:CO", "value": "SA"},
{"key": "continent:EC", "value": "SA"},
{"key": "continent:FK", "value": "SA"},
{"key": "continent:GF", "value": "SA"},
{"key": "continent:GY", "value": "SA"},
{"key": "continent:PY", "value": "SA"},
{"key": "continent:PE", "value": "SA"},
{"key": "continent:SR", "value": "SA"},
{"key": "continent:UY", "value": "SA"},
{"key": "continent:VE", "value": "SA"}
```

### Oceania (OC) - 25 entries
```json
{"key": "continent:AS", "value": "OC"},
{"key": "continent:AU", "value": "OC"},
{"key": "continent:CK", "value": "OC"},
{"key": "continent:FJ", "value": "OC"},
{"key": "continent:PF", "value": "OC"},
{"key": "continent:GU", "value": "OC"},
{"key": "continent:KI", "value": "OC"},
{"key": "continent:MH", "value": "OC"},
{"key": "continent:FM", "value": "OC"},
{"key": "continent:NR", "value": "OC"},
{"key": "continent:NC", "value": "OC"},
{"key": "continent:NZ", "value": "OC"},
{"key": "continent:NU", "value": "OC"},
{"key": "continent:NF", "value": "OC"},
{"key": "continent:MP", "value": "OC"},
{"key": "continent:PW", "value": "OC"},
{"key": "continent:PG", "value": "OC"},
{"key": "continent:PN", "value": "OC"},
{"key": "continent:WS", "value": "OC"},
{"key": "continent:SB", "value": "OC"},
{"key": "continent:TK", "value": "OC"},
{"key": "continent:TO", "value": "OC"},
{"key": "continent:TV", "value": "OC"},
{"key": "continent:VU", "value": "OC"},
{"key": "continent:WF", "value": "OC"}
```

### Antarctica (AN) - 5 entries
```json
{"key": "continent:AQ", "value": "AN"},
{"key": "continent:BV", "value": "AN"},
{"key": "continent:TF", "value": "AN"},
{"key": "continent:HM", "value": "AN"},
{"key": "continent:GS", "value": "AN"}
```

## Total Count

- **Total countries/territories**: 239
- **KVS entries needed**: 239 (with `continent:` prefix)
- **Estimated KVS size**: ~10KB (well within 5MB limit)

**Note**: Only include the countries actually used in Cloudflare rules. If rules only check for Asia (AS) continent, only include the 53 Asian countries in KVS.
