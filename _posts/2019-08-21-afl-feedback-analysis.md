---
title: AFL
author: rk700
layout: post
catalog: true
tags:
  - binary
  - fuzzing
---

为了理解AFL(American Fuzzy Lop)的对共享内存的反馈分析的一些实现细节,特此总结。

## 分支信息的记录（回顾）

现在，用于通信的共享内存已准备完毕，接下来我们看看具体通信的是什么。

由官网文档可知，AFL是根据二元tuple(跳转的源地址和目标地址)来记录分支信息，从而获取target的执行流程和代码覆盖情况，其伪代码如下：

{% highlight bash %}
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++; 
prev_location = cur_location >> 1;
{% endhighlight %}

我们再回到方法`__afl_maybe_log()`中。上面提到，在target完成准备工作后，共享内存的地址被保存在寄存器`edx`中。随后执行以下代码：

{% highlight c %}
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in ecx. There\n"
  "     is a double-XOR way of doing this without tainting another register,\n"
  "     and we use it on 64-bit systems; but it's slower for 32-bit ones. */\n"
  "\n"
#ifndef COVERAGE_ONLY

  "  movl __afl_prev_loc, %edi\n"
  "  xorl %ecx, %edi\n"
  "  shrl $1, %ecx\n"
  "  movl %ecx, __afl_prev_loc\n"
#else

  "  movl %ecx, %edi\n"
#endif /* ^!COVERAGE_ONLY */

  "\n"
#ifdef SKIP_COUNTS

  "  orb  $1, (%edx, %edi, 1)\n"
#else

  "  incb (%edx, %edi, 1)\n"
{% endhighlight %}

这里对应的便正是文档中的伪代码。具体地，变量`__afl_prev_loc`保存的是前一次跳转的"位置"，其值与`ecx`做异或后，保存在`edi`中，并以`edx`（共享内存）为基址，对`edi`下标处进行加一操作。而`ecx`的值右移1位后，保存在了变量`__afl_prev_loc`中。

那么，这里的`ecx`，保存的应该就是伪代码中的`cur_location`了。回忆之前介绍代码插桩的部分：

{% highlight c %}
static const u8* trampoline_fmt_32 = 
...
  "movl $0x%08x, %%ecx\n"
  "call __afl_maybe_log\n"
{% endhighlight %}

在每个插桩处，afl-as会添加相应指令，将`ecx`的值设为0到MAP_SIZE之间的某个随机数，从而实现了伪代码中的`cur_location = <COMPILE_TIME_RANDOM>;`。

因此，AFL为每个代码块生成一个随机数，作为其“位置”的记录；随后，对分支处的”源位置“和”目标位置“进行异或，并将异或的结果作为该分支的key，保存每个分支的执行次数。用于保存执行次数的实际上是一个哈希表，大小为`MAP_SIZE=64K`，当然会存在碰撞的问题；但根据AFL文档中的介绍，对于不是很复杂的目标，碰撞概率还是可以接受的：

{% highlight bash %}

   Branch cnt | Colliding tuples | Example targets
  ------------+------------------+-----------------
        1,000 | 0.75%            | giflib, lzo
        2,000 | 1.5%             | zlib, tar, xz
        5,000 | 3.5%             | libpng, libwebp
       10,000 | 7%               | libxml
       20,000 | 14%              | sqlite
       50,000 | 30%              | -
{% endhighlight %}

如果一个目标过于复杂，那么AFL状态面板中的map_density信息就会有相应的提示：

{% highlight bash %}
┬─ map coverage ─┴───────────────────────┤
│    map density : 3.61% / 14.13%        │
│ count coverage : 6.35 bits/tuple       │
┼─ findings in depth ────────────────────┤
{% endhighlight %}

这里的map density，就是这张哈希表的密度。可以看到，上面示例中，该次执行的哈希表密度仅为3.61%，即整个哈希表差不多有95%的地方还是空的，所以碰撞的概率很小。不过，如果目标很复杂，map density很大，那么就需要考虑到碰撞的影响了。此种情况下的具体处理方式可见官方文档。

另外，比较有意思的是，AFL需要将`cur_location`右移1位后，再保存到`prev_location`中。官方文档中解释了这样做的原因。假设target中存在`A->A`和`B->B`这样两个跳转，如果不右移，那么这两个分支对应的异或后的key都是0，从而无法区分；另一个例子是`A->B`和`B->A`，如果不右移，这两个分支对应的异或后的key也是相同的。

由上述分析可知，之前提到的共享内存，被用于保存一张哈希表，target在这张表中记录每个分支的执行数量。随后，当target执行结束后，fuzzer便开始对这张表进行分析，从而判断代码的执行情况。

---

## 分支信息的分析

首先，fuzzer对`trace_bits`（共享内存）进行预处理：

{% highlight c %}
classify_counts((u32*)trace_bits);
{% endhighlight %}

具体地，target是将每个分支的执行次数用1个byte来储存，而fuzzer则进一步把这个执行次数归入以下的buckets中：

{% highlight c %}
static const u8 count_class_lookup8[256] = {

  [0]           = 0, 
  [1]           = 1, 
  [2]           = 2, 
  [3]           = 4, 
  [4 ... 7]     = 8, 
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};
{% endhighlight %}

举个例子，如果某分支执行了1次，那么落入第2个bucket，其计数byte仍为1；如果某分支执行了4次，那么落入第5个bucket，其计数byte将变为8，等等。

这样处理之后，对分支执行次数就会有一个简单的归类。例如，如果对某个测试用例处理时，分支A执行了32次；对另外一个测试用例，分支A执行了33次，那么AFL就会认为这两次的代码覆盖是相同的。当然，这样的简单分类肯定不能区分所有的情况，不过在某种程度上，处理了一些因为循环次数的微小区别，而误判为不同执行结果的情况。

共享内存存储在trace_bits中，此时统计的都是真实的执行次数(一字不差)。由于我们只关心这些执行次数的大致范围，因此就按照`count_class_lookup8`给出的映射关系对其进行削抹。削抹得到规整后的（”无毛刺“）的直方图。
完成此统计工作的是`classify_counts`函数.
{% highlight c %}
static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}
{% endhighlight %}

该函数在子进程结束（也就是完成一次测试后）时调用。具体场景：
{% highlight c %}
    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

    }

  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */
{% endhighlight %}

随后，对于某些mutated input来说，如果这次执行没有出现崩溃等异常输出，fuzzer还会检查其是否新增了执行路径。具体来说，是对`trace_bits`计算hash并来实现：

{% highlight c %}
u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
{% endhighlight %}

通过比较hash值，就可以判断`trace_bits`是否发生了变化，从而判断此次mutated input是否带来了新路径，为之后的fuzzing提供参考信息。

## 总结

以上便是对AFL内部细节的一些分析整理，其实还有很多地方值得进一步深入去研究，例如AFL是如何判断一条路径是否是favorite的、如何对seed文件进行变化，等等。如果只是使用AFL进行简单的fuzzing，那么这些细节其实不需要掌握太多；但是如果需要在AFL的基础上进一步针对特定目标进行优化，那么了解AFL的内部工作原理就是必须的了。
