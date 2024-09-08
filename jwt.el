;;; jwt.el --- json web tokens for Emacs -*- lexical-binding: t; -*-

;; Copyright (C) 2024 zbelial

;; Author: zbelial <zjyzhaojiyang@gmail.com>
;; Maintainer: zbelial <zjyzhaojiyang@gmail.com>
;; URL: https://github.com/zbelial/jwt.el
;; Package-Requires: ((emacs "25.1") (hmac "0.0"))
;; Version: 0.0.1

;; This file is NOT part of GNU Emacs.

;; jwt is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; jwt is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with axe.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:
;; A jwt implementation for Emacs, only supports HS256 at the moment.

;; Example usage:
;; (let ((secret "secret")
;;       (header '(("alg" . "HS256") ("typ" . "JWT")))
;;       (payload '(("sub" . "1234567890") ("name" . "John Doe") ("iat" . 1516239022))))
;;   (let ((encoded-token (jwt-encode header payload secret 'HS256)))
;;     (message "Encoded JWT: %s" encoded-token)
;;     (let ((decoded (jwt-decode encoded-token secret)))
;;       (when decoded
;;         (message "Decoded JWT: %s" decoded)))))

;;; Code:

(require 'hmac)
(require 'json)

(defun jwt-base64-encode (str)
  "Base64 encode a string."
  (base64-encode-string str))

(defun jwt-base64-decode (str)
  "Base64 decode a string."
  (base64-decode-string str))

(defun jwt--sign(algorithm secret token)
  (cond
   ((equal "HS256" algorithm)
    (hmac 'sha256 secret token))
   (t
    (error "Unsupported algorightm %s" algorithm))))

(defun jwt-encode (header payload secret algorithm)
  "Encode a JWT token."
  (let* ((header-json (json-encode header))
         (payload-json (json-encode payload))
         (unencoded-token (concat header-json "." payload-json))
         (encoded-header (jwt-base64-encode header-json))
         (encoded-payload (jwt-base64-encode payload-json))
         (encoded-token (concat encoded-header "." encoded-payload))
         (signature (jwt--sign "HS256" secret encoded-token)))
    (concat encoded-token "." (jwt-base64-encode signature))))

(defun jwt-decode (token secret)
  "Decode a JWT token."
  (let ((parts (split-string token "\\.")))
    (when (= (length parts) 3)
      (let* ((encoded-header (nth 0 parts))
             (encoded-payload (nth 1 parts))
             (encoded-signature (nth 2 parts))
             (header (json-read-from-string (jwt-base64-decode encoded-header)))
             (payload (json-read-from-string (jwt-base64-decode encoded-payload)))
             (calculated-signature (jwt-base64-encode (jwt--sign (assoc-default 'alg header) secret (concat encoded-header "." encoded-payload)))))
        (when (string= encoded-signature calculated-signature)
          (cons header payload))))))

(provide 'jwt)
