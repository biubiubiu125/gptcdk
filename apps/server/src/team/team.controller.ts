import { Body, Controller, Get, Param, ParseIntPipe, Patch, Post, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TeamService } from './team.service';

@Controller('admin/team')
@UseGuards(JwtAuthGuard)
export class TeamController {
  constructor(private readonly team: TeamService) {}

  @Get('status')
  status() {
    return this.team.status();
  }

  @Get('workspaces')
  list() {
    return this.team.listWorkspaces();
  }

  @Post('workspaces')
  create(@Body() body: { session?: string; socks?: string; workspaceId?: string }) {
    return this.team.createWorkspace(body || {});
  }

  @Get('workspaces/:id/session-preview')
  preview(@Param('id', ParseIntPipe) id: number) {
    return this.team.previewSession(id);
  }

  @Get('workspaces/:id/session')
  reveal(@Param('id', ParseIntPipe) id: number) {
    return this.team.revealSession(id);
  }

  @Patch('workspaces/:id')
  update(@Param('id', ParseIntPipe) id: number, @Body() body: { session?: string; socks?: string; workspaceId?: string; clearSocks?: boolean }) {
    return this.team.updateWorkspace(id, body || {});
  }

  @Post('workspaces/:id/assign')
  assign(@Param('id', ParseIntPipe) id: number) {
    return this.team.assign(id);
  }

  @Post('workspaces/:id/probe')
  probe(@Param('id', ParseIntPipe) id: number) {
    return this.team.probe(id);
  }

  @Post('workspaces/:id/refresh')
  refresh(@Param('id', ParseIntPipe) id: number) {
    return this.team.refresh(id);
  }

  @Get('workspaces/:id/kick-preview')
  previewKick(@Param('id', ParseIntPipe) id: number) {
    return this.team.previewKickAll(id);
  }

  @Post('workspaces/:id/kick-all')
  kickAll(@Param('id', ParseIntPipe) id: number, @Body() body: { confirm?: string; userIds?: string[] }) {
    return this.team.kickAll(id, String(body?.confirm || ''), Array.isArray(body?.userIds) ? body.userIds : []);
  }

  @Post('workspaces/:id/kick-selected')
  kickSelected(@Param('id', ParseIntPipe) id: number, @Body() body: { confirm?: string; userIds?: string[] }) {
    return this.team.kickSelected(id, String(body?.confirm || ''), Array.isArray(body?.userIds) ? body.userIds : []);
  }

  @Post('workspaces/:id/revoke-invites')
  revoke(@Param('id', ParseIntPipe) id: number) {
    return this.team.revokeInvites(id);
  }

  @Get('members')
  members(@Query('workspaceId') workspaceId?: string) {
    const id = Number(workspaceId);
    return this.team.listMembers(Number.isFinite(id) && id > 0 ? id : undefined);
  }

  @Get('remote-members')
  remoteMembers() {
    return this.team.listRemoteMembers();
  }

  @Get('waiting')
  waiting() {
    return this.team.listWaiting();
  }

  @Get('jobs')
  jobs() {
    return this.team.listJobs();
  }

  @Post('import')
  importChildren(@Body() body: { text?: string }) {
    return this.team.importChildren(String(body?.text || ''));
  }

  @Get('children/:id/secret')
  child(@Param('id', ParseIntPipe) id: number) {
    return this.team.revealChild(id);
  }

  @Patch('children/:id/proxy')
  childProxy(@Param('id', ParseIntPipe) id: number, @Body() body: { socks?: string }) {
    return this.team.updateChildProxy(id, String(body?.socks || ''));
  }

  @Post('children/:id/kick')
  kick(@Param('id', ParseIntPipe) id: number) {
    return this.team.kickOne(id);
  }
}
