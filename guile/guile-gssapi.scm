;  Copyright (C) 2021  Peter Kohler
;  
;  This program is free software: you can redistribute it and/or modify
;  it under the terms of the GNU General Public License as published by
;  the Free Software Foundation, either version 3 of the License, or
;  (at your option) any later version.
;  
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;  
;  You should have received a copy of the GNU General Public License
;  along with this program.  If not, see <https://www.gnu.org/licenses/>.

(define-module (guile-gssapi))

(load-extension "libguile-gssapi" "init")
(export gss-import-name)
(export gss-display-name)
;(export oid->list)
(export GSS_KRB5_NT_PRINCIPAL_NAME)
(export GSS_MECH_KRB5)
(export gss-acquire-cred)
(export cred->lifetime)
(export gss-init-sec-context)
(export ctx->lifetime)
(export ctx->deleg)
(export ctx->mutual)
(export ctx->replay)
(export ctx->sequence)
(export ctx->anon)
(export ctx->trans)
(export ctx->prot_ready)
(export ctx->conf_avail)
(export ctx->integ_avail)
(export ctx->lifetime)
(export gss-accept-sec-context)
(export gss-wrap)
(export gss-unwrap)
