/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package sonia.scm.auth.ldap;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * Single sign on token based on header
 *
 */

public final class SsoHeaderAuthenticationToken implements AuthenticationToken {

  private final String username;

  private SsoHeaderAuthenticationToken(String username) {
    this.username = username;
  }

  /**
   * Returns the username
   *
   * @return username
   */
  @Override
  public String getPrincipal() {
    return username;
  }

  /**
   * Returns null, because there will be not stored credentials
   *
   * @return null
   */
  @Override
  public String getCredentials() {
    return null;
  }

  /**
   * Creates a new {@link SsoHeaderAuthenticationToken} from raw string representation for the given ui session id.
   *
   * @param username  name of the user from the Header
   * @return new SsoHeaderAuthenticationToken
   */
  public static SsoHeaderAuthenticationToken create(String username) {
    return new SsoHeaderAuthenticationToken(username);
  }
}

