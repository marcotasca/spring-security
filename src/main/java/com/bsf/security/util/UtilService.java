package com.bsf.security.util;

import jakarta.servlet.http.HttpServletRequest;

public interface UtilService {
    String getAppUrl(HttpServletRequest request);
    String getClientIP(HttpServletRequest request);
}
