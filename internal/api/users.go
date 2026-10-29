package api

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/store"
)

// writeUserStoreErr renders one user-store error for the account endpoints:
// a simpleError is a validation message (no pending enrollment, bad TOTP
// code, ...) — a client-facing fact rendered as-is with 400;
// store.ErrUserNotFound answers 404「用户不存在」(same fact, same code on
// every path that names a user — the middleware-level endpoints and the
// self-service ones alike); any other store failure answers 5xx with a fixed
// Chinese message while the original driver text goes only to the server
// log. Reports whether it rendered (callers return immediately).
func writeUserStoreErr(w http.ResponseWriter, op string, err error) bool {
	if err == nil {
		return false
	}
	var se simpleError
	if errors.As(err, &se) {
		writeErr(w, http.StatusBadRequest, err)
		return true
	}
	if errors.Is(err, store.ErrUserNotFound) {
		writeErr(w, http.StatusNotFound, simpleError("用户不存在"))
		return true
	}
	slog.Error("api: user store operation failed", "op", op, "err", err)
	writeErr(w, http.StatusInternalServerError, simpleError("用户数据操作失败，详情见服务端日志"))
	return true
}

// Roles ordered by privilege level (higher wins).
var roleLevel = map[string]int{
	store.RoleAuditor:  1,
	store.RoleOperator: 2,
	store.RoleAdmin:    3,
}

// RoleAtLeast reports whether the session role satisfies the required level.
func RoleAtLeast(role, required string) bool {
	return roleLevel[role] >= roleLevel[required]
}

// currentUser is attached to the request context by the auth middleware.
type currentUser struct {
	Username string
	Role     string
}

// roleDisplayName maps a role code to its console-facing Chinese name; the
// raw code is the fallback for unknown values so nothing breaks if a new
// role is added without updating the map.
var roleDisplayName = map[string]string{
	store.RoleAdmin:    "管理员",
	store.RoleOperator: "操作员",
	store.RoleAuditor:  "审计员",
}

func roleLabel(role string) string {
	if n, ok := roleDisplayName[role]; ok {
		return n
	}
	return role
}

// requireRole answers 401 for a request without a resolved identity (same
// code and message as the auth middleware, review S-13) and 403 when the
// session role is below the required one (legacy single-admin sessions carry
// role admin). When console auth is disabled (dev mode) all operations are
// allowed.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, required string) bool {
	if s.opts.Auth == nil || s.opts.Auth.hash == "" {
		return true // auth disabled (dev mode)
	}
	u := userFromContext(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, simpleError("未登录或会话已失效，请重新登录"))
		return false
	}
	if !RoleAtLeast(u.Role, required) {
		writeErr(w, http.StatusForbidden, simpleError("权限不足：该操作需要"+roleLabel(required)+"（"+required+"）权限"))
		return false
	}
	return true
}

// userStore returns the users store (nil when the console DB is unavailable,
// e.g. pure API tests).
func (s *Server) userStore() *store.Store { return s.opts.Center.Store() }

// Default bootstrap account: created on first boot with an empty users
// table when no legacy admin hash is configured. The initial password is NOT
// baked into the binary: it comes from KMWAF_BOOTSTRAP_PASSWORD, or is
// generated per install and written to a 0600 file next to the console DB. The
// first login must change it before the console is usable.
const (
	bootstrapUsername = "kmadmin"
	// bootstrapPasswordEnv lets the operator pin the first-boot password
	// (automated installs / test harnesses). The value is never logged.
	bootstrapPasswordEnv = "KMWAF_BOOTSTRAP_PASSWORD"
	// bootstrapPasswordFile is written next to the console DB on first boot
	// when the env override is absent; read it once and delete it.
	bootstrapPasswordFile = "initial-admin-password.txt"
)

// bootstrapAlphabet avoids look-alike characters (0/O, 1/l/I) so the generated
// password survives being copied off a console screen.
const bootstrapAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789@#%+="

// generateBootstrapPassword returns a 24-character random password.
func generateBootstrapPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = bootstrapAlphabet[int(b)%len(bootstrapAlphabet)]
	}
	return string(out), nil
}

// writeBootstrapPassword stores the generated password next to the console DB
// with owner-only permissions and returns its path.
func (s *Server) writeBootstrapPassword(pw string) (string, error) {
	dir := filepath.Dir(s.opts.Center.DBPath())
	path := filepath.Join(dir, bootstrapPasswordFile)
	if err := os.WriteFile(path, []byte(pw+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// ensureAdminSeed creates the first-boot bootstrap account the first time the
// console starts with an empty users table: the kmadmin account with an
// operator-supplied or freshly generated password, forced into a password
// change at first login. This is the ONLY account the product ever creates
// automatically.
func (s *Server) ensureAdminSeed() {
	st := s.userStore()
	if st == nil {
		return
	}
	n, err := st.CountUsers()
	if err != nil || n > 0 {
		return
	}
	pw := strings.TrimSpace(os.Getenv(bootstrapPasswordEnv))
	generated := pw == ""
	if generated {
		pw, err = generateBootstrapPassword()
		if err != nil {
			slog.Error("cannot generate the initial console password", "err", err)
			return
		}
	}
	hash, herr := passhash.HashPassword(pw)
	if herr != nil {
		return
	}
	if _, cerr := st.CreateUserInitial(bootstrapUsername, hash, store.RoleAdmin); cerr != nil {
		return
	}
	if !generated {
		slog.Warn("default console account created", "username", bootstrapUsername,
			"password_source", bootstrapPasswordEnv, "action", "first login forces a password change")
		return
	}
	path, werr := s.writeBootstrapPassword(pw)
	if werr != nil {
		slog.Error("default console account created but the initial password could not be stored",
			"username", bootstrapUsername, "err", werr,
			"action", "set "+bootstrapPasswordEnv+" and recreate the account")
		return
	}
	slog.Warn("default console account created", "username", bootstrapUsername,
		"password_file", path, "action", "read the file, delete it, and change the password at first login")
}

// handleUserList returns all console accounts (admin only).
func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	users, err := s.userStore().ListUsers()
	if err != nil {
		writeUserStoreErr(w, "user.list", err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// handleUserResetPassword generates a one-time temporary password for the
// target account (admin only): the password is returned once, the account is
// forced into a password change at the next login, and the action is audited.
// Admins cannot reset their own account here (use self-service instead).
func (s *Server) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	if me := userFromContext(r); me != nil && me.Username == username {
		writeErr(w, http.StatusBadRequest, simpleError("修改本人密码请使用「修改密码」自助入口"))
		return
	}
	st := s.userStore()
	if _, err := st.GetUser(username); err != nil {
		writeUserStoreErr(w, "user.reset_password.lookup", err)
		return
	}
	tempPassword, err := generateTempPassword()
	if err != nil {
		slog.Error("api: temp password generation failed", "op", "user.reset_password", "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("生成临时密码失败，详情见服务端日志"))
		return
	}
	hash, err := passhash.HashPassword(tempPassword)
	if err != nil {
		slog.Error("api: password hash failed", "op", "user.reset_password", "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("密码处理失败，详情见服务端日志"))
		return
	}
	if err := st.ResetUserPassword(username, hash); err != nil {
		writeUserStoreErr(w, "user.reset_password", err)
		return
	}
	s.recordChange(r, "user.reset_password", username, "temporary password issued (must change at next login)")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": username,
		"temp_password": tempPassword, "must_change": true,
	})
}

// generateTempPassword returns a 20-char alphanumeric one-time password.
func generateTempPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 20)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}

// handleUserCreate adds a console account (admin only).
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, simpleError("用户名不能为空"))
		return
	}
	if err := s.cfgSecurity().ValidatePassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}
	if !store.ValidRole(req.Role) {
		writeErr(w, http.StatusBadRequest, simpleError("角色必须为管理员（admin）、操作员（operator）或审计员（auditor）之一"))
		return
	}
	hash, err := passhash.HashPassword(req.Password)
	if err != nil {
		slog.Error("api: password hash failed", "op", "user.create", "err", err)
		writeErr(w, http.StatusInternalServerError, simpleError("创建用户失败，详情见服务端日志"))
		return
	}
	// 预查重复名：把 SQLite 的 UNIQUE 约束错误译成明确提示。
	if _, gerr := s.userStore().GetUser(req.Username); gerr == nil {
		writeErr(w, http.StatusBadRequest, simpleError("用户名已存在"))
		return
	}
	if _, err := s.userStore().CreateUser(req.Username, hash, req.Role); err != nil {
		// Same classifier as every other user-store endpoint (S-6 family):
		// a store failure is a 5xx with a fixed message (the original text
		// goes to the server log), never a 400 asking the admin to "retry".
		writeUserStoreErr(w, "user.create", err)
		return
	}
	s.recordChange(r, "user.create", req.Username, "role="+req.Role)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username, "role": req.Role})
}

// handleUserUpdate changes role/password/disabled flags (admin only).
// Deleting or demoting the last enabled admin is refused to avoid lockout.
func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	target, err := st.GetUser(username)
	if err != nil {
		writeUserStoreErr(w, "user.update.lookup", err)
		return
	}
	var req struct {
		Role     *string `json:"role,omitempty"`
		Password *string `json:"password,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
		Email    *string `json:"email,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var changes []string

	if req.Email != nil && strings.TrimSpace(*req.Email) != target.Email {
		if err := st.SetUserEmail(username, strings.TrimSpace(*req.Email)); err != nil {
			writeUserStoreErr(w, "user.update-email", err)
			return
		}
		changes = append(changes, "email updated")
	}

	if req.Role != nil && *req.Role != target.Role {
		// Same pre-check as user creation: reject an unknown role code with
		// a clean 400 instead of letting it fall through to the store layer.
		if !store.ValidRole(*req.Role) {
			writeErr(w, http.StatusBadRequest, simpleError("角色必须为管理员（admin）、操作员（operator）或审计员（auditor）之一"))
			return
		}
		if err := s.guardLastAdmin(st, username, func() error { return st.UpdateUserRole(username, *req.Role) }); err != nil {
			// Classifier handles both faces: business refusal (simpleError)
			// → 400, store failure → fixed 500 + server log.
			writeUserStoreErr(w, "user.update-role", err)
			return
		}
		changes = append(changes, "role="+*req.Role)
	}
	if req.Disabled != nil && *req.Disabled != target.Disabled {
		if err := s.guardLastAdmin(st, username, func() error { return st.UpdateUserDisabled(username, *req.Disabled) }); err != nil {
			// Same dual-face classification as the role change above.
			writeUserStoreErr(w, "user.update-disabled", err)
			return
		}
		if *req.Disabled {
			changes = append(changes, "disabled")
		} else {
			changes = append(changes, "enabled")
		}
	}
	if req.Password != nil {
		if err := s.cfgSecurity().ValidatePassword(*req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
			return
		}
		if err := s.rejectPasswordReuse(st, username, target.PasswordHash, *req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
			return
		}
		hash, err := passhash.HashPassword(*req.Password)
		if err != nil {
			slog.Error("api: password hash failed", "op", "user.update-password", "err", err)
			writeErr(w, http.StatusInternalServerError, simpleError("密码处理失败，详情见服务端日志"))
			return
		}
		if err := st.UpdateUserPassword(username, hash, s.cfgSecurity().PasswordHistoryCountOrDefault()); err != nil {
			// Same error surface as user creation (review S-6 / F-2): the
			// driver text must not reach the client — writeUserStoreErr
			// classifies it (validation/simpleError → 400, unknown → fixed
			// 500 message with the original only in the server log).
			writeUserStoreErr(w, "user.update-password", err)
			return
		}
		changes = append(changes, "password reset")
	}
	if len(changes) > 0 {
		s.recordChange(r, "user.update", username, strings.Join(changes, ", "))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserDelete removes an account (admin only; last enabled admin is
// protected).
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	if err := s.guardLastAdmin(st, username, func() error { return st.DeleteUser(username) }); err != nil {
		// Same dual-face classification as handleUserUpdate.
		writeUserStoreErr(w, "user.delete", err)
		return
	}
	s.recordChange(r, "user.delete", username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// guardLastAdmin refuses an operation when it would leave the console with
// no enabled admin account.
func (s *Server) guardLastAdmin(st *store.Store, username string, op func() error) error {
	target, err := st.GetUser(username)
	if err != nil {
		return err
	}
	if target.Role != store.RoleAdmin || target.Disabled {
		return op()
	}
	users, err := st.ListUsers()
	if err != nil {
		return err
	}
	enabledAdmins := 0
	for _, u := range users {
		if u.Role == store.RoleAdmin && !u.Disabled {
			enabledAdmins++
		}
	}
	if enabledAdmins <= 1 {
		return simpleError("拒绝操作：不能删除或停用最后一个已启用的管理员账号")
	}
	return op()
}
