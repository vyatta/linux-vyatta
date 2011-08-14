/*  linux/include/linux/tick.h
 *
 *  This file contains the structure definitions for tick related functions
 *
 */
#ifndef _LINUX_TICK_H
#define _LINUX_TICK_H

#include <linux/clockchips.h>
#include <linux/irqflags.h>

#ifdef CONFIG_GENERIC_CLOCKEVENTS

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE,
	NOHZ_MODE_LOWRES,
	NOHZ_MODE_HIGHRES,
};

enum tick_saved_jiffies {
	JIFFIES_SAVED_NONE,
	JIFFIES_SAVED_IDLE,
	JIFFIES_SAVED_USER,
	JIFFIES_SAVED_SYS,
};

/**
 * struct tick_sched - sched tick emulation and no idle tick control/stats
 * @sched_timer:		hrtimer to schedule the periodic tick in high
 *				resolution mode
 * @last_tick:			Store the last tick expiry time when the tick
 *				timer is modified for nohz sleeps. This is necessary
 *				to resume the tick timer operation in the timeline
 *				when the CPU returns from nohz sleep.
 * @tick_stopped:		Indicator that the idle tick has been stopped
 * @idle_calls:			Total number of idle calls
 * @idle_sleeps:		Number of idle calls, where the sched tick was stopped
 * @idle_entrytime:		Time when the idle call was entered
 * @idle_waketime:		Time when the idle was interrupted
 * @idle_exittime:		Time when the idle state was left
 * @idle_sleeptime:		Sum of the time slept in idle with sched tick stopped
 * @saved_jiffies:		Jiffies snapshot on tick stop for cpu time accounting
 * @saved_jiffies_whence:	Area where we saved @saved_jiffies
 * @iowait_sleeptime:		Sum of the time slept in idle with sched tick stopped, with IO outstanding
 * @sleep_length:		Duration of the current idle sleep
 * @do_timer_lst:		CPU was the last one doing do_timer before going idle
 */
struct tick_sched {
	struct hrtimer			sched_timer;
	unsigned long			check_clocks;
	enum tick_nohz_mode		nohz_mode;
	ktime_t				last_tick;
	int				inidle;
	int				tick_stopped;
	unsigned long			idle_calls;
	unsigned long			idle_sleeps;
	int				idle_active;
	ktime_t				idle_entrytime;
	ktime_t				idle_waketime;
	ktime_t				idle_exittime;
	ktime_t				idle_sleeptime;
	enum tick_saved_jiffies		saved_jiffies_whence;
	unsigned long			saved_jiffies;
	ktime_t				iowait_sleeptime;
	ktime_t				sleep_length;
	unsigned long			last_jiffies;
	unsigned long			next_jiffies;
	ktime_t				idle_expires;
	int				do_timer_last;
};

extern void __init tick_init(void);
extern int tick_is_oneshot_available(void);
extern struct tick_device *tick_get_device(int cpu);

# ifdef CONFIG_HIGH_RES_TIMERS
extern int tick_init_highres(void);
extern int tick_program_event(ktime_t expires, int force);
extern void tick_setup_sched_timer(void);
# endif

# if defined CONFIG_NO_HZ || defined CONFIG_HIGH_RES_TIMERS
extern void tick_cancel_sched_timer(int cpu);
# else
static inline void tick_cancel_sched_timer(int cpu) { }
# endif

# ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
extern struct tick_device *tick_get_broadcast_device(void);
extern struct cpumask *tick_get_broadcast_mask(void);

#  ifdef CONFIG_TICK_ONESHOT
extern struct cpumask *tick_get_broadcast_oneshot_mask(void);
#  endif

# endif /* BROADCAST */

# ifdef CONFIG_TICK_ONESHOT
extern void tick_clock_notify(void);
extern int tick_check_oneshot_change(int allow_nohz);
extern struct tick_sched *tick_get_tick_sched(int cpu);
extern void tick_check_idle(int cpu);
extern int tick_oneshot_mode_active(void);
#  ifndef arch_needs_cpu
#   define arch_needs_cpu(cpu) (0)
#  endif
# else
static inline void tick_clock_notify(void) { }
static inline int tick_check_oneshot_change(int allow_nohz) { return 0; }
static inline void tick_check_idle(int cpu) { }
static inline int tick_oneshot_mode_active(void) { return 0; }
# endif

#else /* CONFIG_GENERIC_CLOCKEVENTS */
static inline void tick_init(void) { }
static inline void tick_cancel_sched_timer(int cpu) { }
static inline void tick_clock_notify(void) { }
static inline int tick_check_oneshot_change(int allow_nohz) { return 0; }
static inline void tick_check_idle(int cpu) { }
static inline int tick_oneshot_mode_active(void) { return 0; }
#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

# ifdef CONFIG_NO_HZ
extern void tick_nohz_idle_enter(void);
extern void tick_nohz_idle_exit(void);
extern void tick_nohz_restart_sched_tick(void);
extern void tick_nohz_irq_exit(void);
extern ktime_t tick_nohz_get_sleep_length(void);
extern u64 get_cpu_idle_time_us(int cpu, u64 *last_update_time);
extern u64 get_cpu_iowait_time_us(int cpu, u64 *last_update_time);
# else /* !NO_HZ */
static inline void tick_nohz_idle_enter(void) { }
static inline void tick_nohz_idle_exit(void) { }

static inline ktime_t tick_nohz_get_sleep_length(void)
{
	ktime_t len = { .tv64 = NSEC_PER_SEC/HZ };

	return len;
}
static inline u64 get_cpu_idle_time_us(int cpu, u64 *unused) { return -1; }
static inline u64 get_cpu_iowait_time_us(int cpu, u64 *unused) { return -1; }
# endif /* !NO_HZ */

#ifdef CONFIG_CPUSETS_NO_HZ
extern void tick_nohz_enter_kernel(void);
extern void tick_nohz_exit_kernel(void);
extern void tick_nohz_enter_exception(struct pt_regs *regs);
extern void tick_nohz_exit_exception(struct pt_regs *regs);
extern void tick_nohz_check_adaptive(void);
extern void tick_nohz_pre_schedule(void);
extern void tick_nohz_post_schedule(void);
extern bool tick_nohz_account_tick(void);
extern void tick_nohz_flush_current_times(bool restart_tick);
#else /* !CPUSETS_NO_HZ */
static inline void tick_nohz_enter_kernel(void) { }
static inline void tick_nohz_exit_kernel(void) { }
static inline void tick_nohz_enter_exception(struct pt_regs *regs) { }
static inline void tick_nohz_exit_exception(struct pt_regs *regs) { }
static inline void tick_nohz_check_adaptive(void) { }
static inline void tick_nohz_pre_schedule(void) { }
static inline void tick_nohz_post_schedule(void) { }
static inline bool tick_nohz_account_tick(void) { return false; }
#endif /* CPUSETS_NO_HZ */

#endif
