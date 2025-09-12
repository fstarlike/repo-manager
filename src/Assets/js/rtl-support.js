/**
 * Repo Manager — RTL Support (modernized)
 *
 * Strategy: let CSS handle almost everything. This script only:
 * - Detects RTL from WP/env reliably
 * - Sets `dir` and helper classes on the main wrapper
 * - Mirrors a few dynamic UI bits that CSS cannot infer (directory selector, troubleshooting)
 * - Observes DOM changes and reapplies minimal adjustments
 */

(function () {
    "use strict";

    var currentLocale = "en";
    var currentRTL = false;

    function getLocale() {
        try {
            if (
                typeof gitManagerLanguage !== "undefined" &&
                gitManagerLanguage.locale
            ) {
                return gitManagerLanguage.locale;
            }
        } catch (e) {}

        try {
            if (typeof wp !== "undefined" && wp.locale) {
                return wp.locale;
            }
        } catch (e) {}

        return document.documentElement.lang || "en";
    }

    function isWordPressRTL() {
        try {
            if (
                typeof gitManagerLanguage !== "undefined" &&
                typeof gitManagerLanguage.rtl !== "undefined"
            ) {
                return !!gitManagerLanguage.rtl;
            }
        } catch (e) {}

        // Fallback to document
        return (document.documentElement.dir || "").toLowerCase() === "rtl";
    }

    function isLanguageRTL(locale) {
        var rtlLanguages = [
            "ar",
            "he",
            "fa",
            "ur",
            "ps",
            "sd",
            "yi",
            "ku",
            "dv",
            "ckb",
        ];
        var lc = (locale || "en").toLowerCase();
        return rtlLanguages.some(function (code) {
            return lc.indexOf(code) === 0;
        });
    }

    function getWrapper() {
        return document.querySelector(".repo-manager-wrap");
    }

    function applyBaseAttributes(wrapper, rtl) {
        if (!wrapper) return;
        wrapper.setAttribute("dir", rtl ? "rtl" : "ltr");
        wrapper.classList.toggle("repo-manager-rtl", rtl);
        document.body.classList.toggle("repo-manager-rtl-active", rtl);
    }

    // Minimal JS adjustments that CSS alone can't infer
    function adjustDirectorySelector(wrapper, rtl) {
        if (!wrapper || !rtl) return;

        var searchContainer = wrapper.querySelector(".new-search-container");
        if (searchContainer) {
            searchContainer.style.textAlign = "right";
        }

        var searchWrapper = wrapper.querySelector(".new-search-wrapper");
        if (searchWrapper) {
            if (getComputedStyle(searchWrapper).flexDirection !== "column") {
                searchWrapper.style.flexDirection = "row-reverse";
            }
        }

        var searchIcon = wrapper.querySelector(".new-search-icon");
        if (searchIcon) {
            var cs = getComputedStyle(searchIcon);
            if (cs.left !== "auto") {
                searchIcon.style.right = cs.left;
                searchIcon.style.left = "auto";
            }
        }

        var searchClear = wrapper.querySelector(".new-search-clear");
        if (searchClear) {
            var cs2 = getComputedStyle(searchClear);
            if (cs2.right !== "auto") {
                searchClear.style.left = cs2.right;
                searchClear.style.right = "auto";
            }
        }

        var searchInput = wrapper.querySelector(".new-search-input-enhanced");
        if (searchInput) {
            var cs3 = getComputedStyle(searchInput);
            if (cs3.paddingLeft !== "0px" || cs3.paddingRight !== "0px") {
                searchInput.style.paddingLeft = cs3.paddingRight;
                searchInput.style.paddingRight = cs3.paddingLeft;
            }
        }
    }

    function adjustTroubleshoot(wrapper, rtl) {
        if (!wrapper || !rtl) return;

        var title = wrapper.querySelector(".troubleshoot-title");
        if (title && getComputedStyle(title).flexDirection !== "column") {
            title.style.flexDirection = "row-reverse";
        }

        var progress = wrapper.querySelector(".troubleshoot-progress");
        if (progress && getComputedStyle(progress).flexDirection !== "column") {
            progress.style.flexDirection = "row-reverse";
        }
    }

    function applyAdjustments() {
        var wrapper = getWrapper();
        if (!wrapper) return;

        currentLocale = getLocale();
        currentRTL = isWordPressRTL() || isLanguageRTL(currentLocale);

        applyBaseAttributes(wrapper, currentRTL);
        adjustDirectorySelector(wrapper, currentRTL);
        adjustTroubleshoot(wrapper, currentRTL);
    }

    function observeDynamicContent() {
        var obs = new MutationObserver(function (mutations) {
            var needsReapply = false;
            for (var i = 0; i < mutations.length; i++) {
                var m = mutations[i];
                if (
                    m.type === "childList" &&
                    m.addedNodes &&
                    m.addedNodes.length
                ) {
                    for (var j = 0; j < m.addedNodes.length; j++) {
                        var node = m.addedNodes[j];
                        if (node.nodeType === 1 /* ELEMENT_NODE */) {
                            if (
                                node.classList &&
                                node.classList.contains("repo-manager-wrap")
                            ) {
                                needsReapply = true;
                                break;
                            }
                            if (
                                node.querySelector &&
                                node.querySelector(".repo-manager-wrap")
                            ) {
                                needsReapply = true;
                                break;
                            }
                            if (
                                node.classList &&
                                (node.classList.contains(
                                    "new-directory-selector-modal"
                                ) ||
                                    node.classList.contains(
                                        "new-directory-browser"
                                    ) ||
                                    node.classList.contains(
                                        "troubleshoot-container"
                                    ) ||
                                    node.classList.contains(
                                        "troubleshoot-step"
                                    ))
                            ) {
                                needsReapply = true;
                                break;
                            }
                        }
                    }
                }
                if (needsReapply) break;
            }

            if (needsReapply) {
                applyAdjustments();
            }
        });

        obs.observe(document.body, { childList: true, subtree: true });
    }

    // Expose minimal backward-compatible API
    function exposeAPI() {
        try {
            window.gitManagerRTL = {
                isRTLActive: function () {
                    return !!currentRTL;
                },
                getCurrentLanguage: function () {
                    return currentLocale;
                },
                toggleRTL: function () {
                    var wrapper = getWrapper();
                    currentRTL = !currentRTL;
                    applyBaseAttributes(wrapper, currentRTL);
                    adjustDirectorySelector(wrapper, currentRTL);
                    adjustTroubleshoot(wrapper, currentRTL);
                },
                setLanguage: function (lang) {
                    if (typeof lang === "string" && lang) {
                        currentLocale = lang;
                    }
                    // Recompute based on explicit locale + WP preference
                    currentRTL =
                        isWordPressRTL() || isLanguageRTL(currentLocale);
                    var wrapper = getWrapper();
                    applyBaseAttributes(wrapper, currentRTL);
                    adjustDirectorySelector(wrapper, currentRTL);
                    adjustTroubleshoot(wrapper, currentRTL);
                },
            };
        } catch (e) {}
    }

    // Init
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function () {
            applyAdjustments();
            exposeAPI();
            observeDynamicContent();
            window.addEventListener("resize", applyAdjustments);
        });
    } else {
        applyAdjustments();
        exposeAPI();
        observeDynamicContent();
        window.addEventListener("resize", applyAdjustments);
    }
})();
