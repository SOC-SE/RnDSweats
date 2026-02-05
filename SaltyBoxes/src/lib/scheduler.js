/**
 * Simple Scheduler
 *
 * Manages periodic tasks using setInterval.
 * Each schedule has an ID, metadata, and a callback.
 *
 * @module lib/scheduler
 */

class Scheduler {
  constructor() {
    this.schedules = new Map();
    this.nextId = 1;
  }

  /**
   * Create a new scheduled task.
   * @param {object} opts
   * @param {string} opts.name - Human-readable name
   * @param {string} opts.targets - Salt target string
   * @param {string[]} opts.checks - Check types to run
   * @param {number} opts.intervalMinutes - Interval in minutes
   * @param {string} opts.baselineId - Baseline to compare against
   * @param {function} opts.callback - Async function called on each tick
   * @returns {string} Schedule ID
   */
  create({ name, targets, checks, intervalMinutes, baselineId, callback }) {
    const id = String(this.nextId++);
    const intervalMs = intervalMinutes * 60 * 1000;

    const timer = setInterval(async () => {
      try {
        await callback(id);
      } catch (err) {
        // Errors handled by callback
      }
    }, intervalMs);

    this.schedules.set(id, {
      id,
      name: name || `Schedule ${id}`,
      targets,
      checks,
      intervalMinutes,
      baselineId,
      created: new Date().toISOString(),
      lastRun: null,
      timer
    });

    return id;
  }

  /**
   * Delete a schedule.
   * @param {string} id
   * @returns {boolean} Whether the schedule existed
   */
  delete(id) {
    const schedule = this.schedules.get(id);
    if (!schedule) return false;
    clearInterval(schedule.timer);
    this.schedules.delete(id);
    return true;
  }

  /**
   * List all active schedules (without timer references).
   * @returns {object[]}
   */
  list() {
    const result = [];
    for (const [, s] of this.schedules) {
      result.push({
        id: s.id,
        name: s.name,
        targets: s.targets,
        checks: s.checks,
        intervalMinutes: s.intervalMinutes,
        baselineId: s.baselineId,
        created: s.created,
        lastRun: s.lastRun
      });
    }
    return result;
  }

  /**
   * Update lastRun timestamp for a schedule.
   * @param {string} id
   */
  markRun(id) {
    const schedule = this.schedules.get(id);
    if (schedule) {
      schedule.lastRun = new Date().toISOString();
    }
  }

  /**
   * Shut down all schedules.
   */
  shutdown() {
    for (const [, s] of this.schedules) {
      clearInterval(s.timer);
    }
    this.schedules.clear();
  }
}

module.exports = new Scheduler();
