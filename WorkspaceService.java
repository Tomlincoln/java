package com.epam.xm.service.workspace;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.epam.xm.dal.user.UserDao;
import com.epam.xm.dal.user.domain.RoleEntity;
import com.epam.xm.dal.user.domain.UserEntityRole;
import com.epam.xm.dal.user.transformer.UserRoleTransformer;
import com.epam.xm.dal.workspace.dao.WorkspaceDao;
import com.epam.xm.domain.context.security.UserRole;
import com.epam.xm.domain.user.XmUser;
import com.epam.xm.domain.user.XmUserRole;
import com.epam.xm.domain.user.exception.UserWithSameRoleException;
import com.epam.xm.domain.workspace.ActiveWorkspaceIdAndRole;
import com.epam.xm.domain.workspace.Workspace;
import com.epam.xm.service.security.context.facade.SecurityContextFacade;
import com.epam.xm.service.security.spring.domain.CoreSpringSecurityContext;

/**
 * Service for getting {@link Workspace}.
 */
@Service
@Transactional
public class WorkspaceService {

    @Autowired
    private WorkspaceDao workspaceDao;
    @Autowired
    private SecurityContextFacade securityContextFacade;
    @Autowired
    private UserRoleTransformer userRoleTransformer;
    @Autowired
    private UserDao userDao;

    /**
     * Get all workspaces.
     *
     * @return set of {@link Workspace}
     */
    public Set<Workspace> getAllWorkspaces() {
        return workspaceDao.getAllWorkspaces();
    }

    /**
     * Get workspace by id.
     *
     * @param id workspace id
     * @return workspace
     */
    public Workspace getWorkspaceById(Long id) {
        return workspaceDao.getById(id);
    }

    /**
     * Get workspace by id.
     *
     * @return workspace
     */
    public Workspace getActiveWorkspace() {
        Long activeWorkspaceId = securityContextFacade.getUserContext().getActiveWorkspaceId();
        return activeWorkspaceId == null ? null : workspaceDao.getById(activeWorkspaceId);
    }

    /**
     * Get the user's active workspace id.
     *
     * @return Long workspace id
     */
    public Optional<Long> getActiveWorkspaceId() {
        return Optional.ofNullable(securityContextFacade.getUserContext().getActiveWorkspaceId());
    }

    /**
     * Get the set of {@link Workspace} what contain the given user with the given role.
     *
     * @param userId id of {@link com.epam.xm.domain.user.XmUser}
     * @param role {@link XmUserRole} of the user
     * @return set of {@link Workspace}
     */
    public Set<Workspace> getWorkspacesByUserIdAndByRole(Long userId, XmUserRole role) {
        var activeWorkspaceIdAndRole = workspaceDao.getActiveWorkspaceIdAndRoleByUserIdAndRoleId(userId, UserRole.values()[role.ordinal()]);
        return activeWorkspaceIdAndRole.getAssignedWorkspacesToUser();
    }

    /**
     * Get the user id from the userContext.
     *
     * @return userId
     */
    public Long getUserIdFromUserContext() {
        return securityContextFacade.getUserContext().getUser().getId();
    }

    /**
     * Get available workspaces of current user.
     *
     * @return set of worksapces
     */
    public Set<Workspace> getWorkspacesOfUser() {
        return waitForLogin();
    }

    private Set<Workspace> waitForLogin() {
        Long userId = securityContextFacade.getUserContext().getUser().getId();
        return userId == null ? waitForLogin() : workspaceDao.getWorkspacesOfUser(userId);
    }

    /**
     * Extends the assignedRoles array, if the user has Examinee or Global admin roles.
     *
     * @param activeWorkspaceIdAndRole activeWorkspaceIdAndRole DTO
     * @return activeWorkspaceIdAndRole activeWorkspaceIdAndRole DTO
     */
    public ActiveWorkspaceIdAndRole extendUserAssignedRoles(ActiveWorkspaceIdAndRole activeWorkspaceIdAndRole) {
        List<UserRole> defaultAssignedRoles = getCoreSpringSecurityContext().getUserContext().getAssignedRoles();

        if (defaultAssignedRoles.contains(UserRole.ROLE_GLOBAL_ADMIN)) {
            activeWorkspaceIdAndRole.getAssignedRolesToWorkspace().add(UserRole.ROLE_GLOBAL_ADMIN);
        }
        if (defaultAssignedRoles.contains(UserRole.ROLE_EXAMINEE)) {
            activeWorkspaceIdAndRole.getAssignedRolesToWorkspace().add(UserRole.ROLE_EXAMINEE);
        }
        return activeWorkspaceIdAndRole;
    }

    private CoreSpringSecurityContext getCoreSpringSecurityContext() {
        return (CoreSpringSecurityContext) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    /**
     * Get roles of user in specified workspace.
     *
     * @param userId id of user
     * @param workspaceId id of specified workspace
     * @return roles of user in workspace
     */
    public Set<XmUserRole> getRolesOfUserByWorkspace(Long userId, Long workspaceId) {
        return workspaceDao.getRolesOfUserByWorkspace(userId, workspaceId).stream().map(r -> userRoleTransformer.transformUserEntityRole(r.getRolename()))
                .collect(Collectors.toSet());
    }

    /**
     * Add user to workspace.
     *
     * @param workspaceId id of workspace
     * @param userId id of user
     * @param role user role
     * @return updated workspace
     */
    public Workspace addUserToWorkspace(Long workspaceId, Long userId, XmUserRole role) {
        Workspace workspace;
        if (userWithRoleExistsInWorkspace(workspaceId, userId, role)) {
            XmUser user = userDao.getUserByUserId(userId);
            throw new UserWithSameRoleException("user already exists", user.getEmail(), role);
        }
        workspace = workspaceDao.addUserToWorkspace(workspaceId, userId, role);
        return workspace;
    }

    private boolean userWithRoleExistsInWorkspace(Long workspaceId, Long userId, XmUserRole role) {
        Set<UserEntityRole> userEntityRoles = workspaceDao.getRolesOfUserByWorkspace(userId, workspaceId).stream().map(RoleEntity::getRolename)
                .collect(Collectors.toSet());
        Set<XmUserRole> xmUserRolesInWorkspace = userRoleTransformer.transformUserEntityRoles(userEntityRoles);
        return xmUserRolesInWorkspace.contains(role);
    }

    /**
     * Revoke role from a user on every workspace(!).
     *
     * @param userId id of user, revoke from
     * @param roleToRevoke role of user to revoke
     */
    public void revokeUserRole(Long userId, XmUserRole roleToRevoke) {
        workspaceDao.revokeUserRole(userId, roleToRevoke);
    }

    /**
     * Revoke user's role from workspace.
     *
     * @param workspaceId id of workspace
     * @param userId id of user
     * @param role user role to revoke
     */
    public void revokeUserRoleFromWorkspace(Long workspaceId, Long userId, XmUserRole role) {
        workspaceDao.revokeUserRoleFromWorkspace(workspaceId, userId, role);
    }

    /**
     * Saves the given workspace.
     *
     * @param workspace to save
     * @return saved workspace
     */
    public Workspace saveWorkspace(Workspace workspace) {
        return workspaceDao.save(workspace);
    }

    /**
     * Update the given workspace.
     *
     * @param workspace workspace with the updated data
     * @param id id of the original workspace
     * @return updated workspace
     */
    public Workspace updateWorkspace(Workspace workspace, Long id) {
        workspace.setId(id);
        return workspaceDao.update(workspace);
    }

}
