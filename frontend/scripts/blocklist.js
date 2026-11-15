/*
 * blocklist.js — TriVex Family Shield master dictionary.
 *
 * Single source of truth for adult & gambling content classification.
 * Used by:
 *   - family_shield.js  (URL classifier / domain matcher)
 *   - background.js     (builds declarativeNetRequest rules from these lists)
 *
 * To add a new site: drop its domain into ADULT_DOMAINS or GAMBLING_DOMAINS.
 * To add a new keyword: drop it into ADULT_KEYWORDS or GAMBLING_KEYWORDS.
 * No other file needs to be changed.
 */

(function (root) {
  "use strict";

  /* ================================================================
     ADULT CONTENT — DOMAINS
     Exact hostname match (www. is stripped before comparison).
     ================================================================ */
  var ADULT_DOMAINS = [
    // ---- Global ----
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
    "redtube.com", "youporn.com", "tube8.com", "porn.com",
    "sex.com", "xxx.com", "beeg.com", "spankbang.com",
    "eporner.com", "hqporner.com", "tnaflix.com", "txxx.com",
    "porntrex.com", "thumbzilla.com", "fuq.com", "daftsex.com",
    "gotporn.com", "spankwire.com", "camwhores.tv", "erome.com",
    "fapello.com", "heavy-r.com", "motherless.com",
    "chaturbate.com", "stripchat.com", "livejasmin.com",
    "bongacams.com", "cam4.com", "myfreecams.com", "flirt4free.com",
    "brazzers.com", "naughtyamerica.com", "bangbros.com",
    "mofos.com", "realitykings.com", "teamskeet.com",
    "playboy.com", "hustler.com", "penthouse.com",
    "onlyfans.com", "manyvids.com", "clips4sale.com",
    "xtube.com", "gaytube.com", "men.com",
    // ---- Indian / Desi ----
    "desi52.com", "desixnxx.net", "desipapa.com",
    "indianporn365.com", "indiansexstories2.net", "indiansex.tv",
    "desiporn.xxx", "desiboobs.com", "desipornvideos.tv",
    "indianxnxx.com", "hindiporn.tv", "desimasala.co",
    "indiansexmms.co", "indianporntube.net", "hotindianporn.mobi",
    "desi.porn", "desimasalaa.com", "indianpornvideos.com",
    "pornind.com", "bollywoodsex.xxx", "indianbfvideos.com",
    "desipornhub.com", "xnxxindian.com", "indiandesixx.com",
    "hotstar18.com", "desihoes.com", "indiangirlsclub.net",
    "bhabhi.xxx", "indiansexclub.net", "dehati.xxx",
    "desimms.com", "mastram.xxx", "desiaunty.com"
  ];

  /* ================================================================
     ADULT CONTENT — KEYWORDS
     Matched against the full URL string (hostname + path).
     Keep these specific enough to avoid false positives.
     ================================================================ */
  var ADULT_KEYWORDS = [
    // English
    "porn", "pornography", "xxx", "erotic", "hentai", "nsfw",
    "adult-content", "explicit-content", "nudity",
    "onlyfans", "chaturbate", "stripchat", "camgirl", "camboy",
    "escort", "sexcam", "livesex", "sexvideo", "freeporn",
    "hotporn", "teenporn", "milfporn", "amateurporn",
    // Indian / Desi / Regional
    "desiporn", "desixnxx", "desipapa", "indianporn",
    "indiansex", "desisex", "desiboobs", "hindiporn",
    "desimasala", "bollywoodsex", "indianxxx", "indianmms",
    "desi52", "dehati", "bhabhi-sex", "desi-sex",
    "mastram", "kamsutra", "antarvasna",
    // Transliterated Hindi/Urdu adult terms (URL-safe forms)
    "chudai", "chut", "lund", "gaand", "randi",
    "bur", "tits-desi", "nude-desi"
  ];

  /* ================================================================
     GAMBLING — DOMAINS
     ================================================================ */
  var GAMBLING_DOMAINS = [
    "bet365.com", "draftkings.com", "fanduel.com", "pokerstars.com",
    "williamhill.com", "betway.com", "888casino.com", "bovada.lv",
    "betfair.com", "ladbrokes.com", "coral.co.uk", "unibet.com",
    "stake.com", "roobet.com", "rollbit.com", "duelbits.com",
    "bc.game", "1xbet.com", "parimatch.com", "bwin.com",
    "betonline.ag", "ggpoker.com", "partypoker.com",
    "casinodays.com", "leovegas.com", "casumo.com",
    "royalvegascasino.com", "jackpotcity.com",
    // Indian-facing
    "cricbaba.com", "fun88.com", "10cric.com", "parimatch.in",
    "1xbet.in", "betway.in", "dafabet.com", "jeetwin.com"
  ];

  /* ================================================================
     GAMBLING — KEYWORDS
     ================================================================ */
  var GAMBLING_KEYWORDS = [
    "casino", "gambling", "betting", "poker", "roulette",
    "blackjack", "sportsbook", "online-slots", "jackpot-casino",
    "sports-bet", "bet365", "betway", "parimatch",
    "cricket-bet", "ipl-bet", "matka", "satta"
  ];

  /* ================================================================
     Export
     ================================================================ */
  var api = {
    ADULT_DOMAINS:    ADULT_DOMAINS,
    ADULT_KEYWORDS:   ADULT_KEYWORDS,
    GAMBLING_DOMAINS: GAMBLING_DOMAINS,
    GAMBLING_KEYWORDS: GAMBLING_KEYWORDS
  };

  root.TriVexBlocklist = api;
  if (typeof window !== "undefined") window.TriVexBlocklist = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
