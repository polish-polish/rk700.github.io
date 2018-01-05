---
title: AFL文件变异一览
author: rk700
layout: post
catalog: true
tags:
  - binary
  - fuzzing
---

[上一篇文章](https://rk700.github.io/2017/12/28/afl-internals/)主要对AFL的一些实现细节进行了分析，但正如文章最后所说，还有很多细节讲到。所以我又另外写了这篇文章，专门介绍AFL是如何对输入文件进行变异的。

总的来讲，AFL维护了一个队列(queue)，每次从这个队列中取出一个文件，对其进行大量变异，并检查运行后是否会引起目标崩溃、发现新路径等结果。变异的主要类型如下：

- bitflip，按位翻转，1变为0，0变为1
- arithmetic，整数加/减算术运算
- interest，把一些特殊内容替换到原文件中
- dictionary，把自动生成或用户提供的token替换/插入到原文件中
- havoc，中文意思是“大破坏”，此阶段会对原文件进行大量变异，具体见下文
- splice，中文意思是“绞接”，此阶段会将两个文件拼接起来得到一个新的文件

其中，前四项bitflip, arithmetic, interest, dictionary是非dumb mode（`-d`）和主fuzzer（`-M`）会进行的操作，由于其变异方式没有随机性，所以也称为deterministic fuzzing；havoc和splice则存在随机性，是所有状况的fuzzer（是否dumb mode、主从fuzzer）都会执行的变异。

以下将对这些变异类型进行具体介绍。

## bitflip

拿到一个原始文件，打头阵的就是bitflip，而且还会根据翻转量/步长进行多种不同的翻转，按照顺序依次为：

- bitflip 1/1，每次翻转**1**个bit，按照每**1**个bit的步长从头开始
- bitflip 2/1，每次翻转相邻的**2**个bit，按照每**1**个bit的步长从头开始
- bitflip 4/1，每次翻转相邻的**4**个bit，按照每**1**个bit的步长从头开始
- bitflip 8/8，每次翻转相邻的**8**个bit，按照每**8**个bit的步长从头开始，即依次对每个byte做翻转
- bitflip 16/8，每次翻转相邻的**16**个bit，按照每**8**个bit的步长从头开始，即依次对每个word做翻转
- bitflip 32/8，每次翻转相邻的**32**个bit，按照每**8**个bit的步长从头开始，即依次对每个dword做翻转

作为精妙构思的fuzzer，AFL不会放过每一个获取文件信息的机会。这一点在bitflip过程中就体现的淋漓尽致。具体地，在上述过程中，AFL巧妙地嵌入了一些对文件格式的启发式判断。

#### 自动检测token

在进行bitflip 1/1变异时，对于每个byte的最低位(least significant bit)翻转还进行了额外的处理：如果连续多个bytes的最低位被翻转后，程序的执行路径都未变化，而且与原始执行路径不一致(检测程序执行路径的方式可见上篇文章中[“分支信息的分析”](https://rk700.github.io/2017/12/28/afl-internals/#%E5%88%86%E6%94%AF%E4%BF%A1%E6%81%AF%E7%9A%84%E5%88%86%E6%9E%90)一节)，那么就把这一段连续的bytes判断是一条token。

例如，PNG文件中用`IHDR`作为起始块的标识，那么就会存在类似于以下的内容：

```
........IHDR........
```

当翻转到字符`I`的最高位时，因为`IHDR`被破坏，此时程序的执行路径肯定与处理正常文件的路径是不同的；随后，在翻转接下来3个字符的最高位时，`IHDR`标识同样被破坏，程序应该会采取同样的执行路径。由此，AFL就判断得到一个可能的token：`IHDR`，并将其记录下来为后面的变异提供备选。

AFL采取的这种方式是非常巧妙的：就本质而言，这实际上是对每个byte进行修改并检查执行路径；但集成到bitflip后，就不需要再浪费额外的执行资源了。此外，为了控制这样自动生成的token的大小和数量，AFL还在`config.h`中通过宏定义了限制：

```c
/* Length limits for auto-detected dictionary tokens: */

#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32

/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
   (first value), and to keep in memory as candidates. The latter should be much
   higher than the former. */

#define USE_AUTO_EXTRAS     10

#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)
```

对于一些文件来说，我们已知其格式中出现的token长度不会超过4，那么我们就可以修改`MAX_AUTO_EXTRA`为4并重新编译AFL，以排除一些明显不会是token的情况。遗憾的是，这些设置是通过宏定义来实现，所以不能做到运行时指定，每次修改后必须重新编译AFL。

#### 生成effector map

在进行bitflip 8/8变异时，AFL还生成了一个非常重要的信息：effector map。这个effector map几乎贯穿了整个deterministic fuzzing的始终。

具体地，在对每个byte进行翻转时，如果其造成执行路径与原始路径不一致，就将该byte在effector map中标记为1，即“有效”的，否则标记为0，即“无效”的。

这样做的逻辑是：如果一个byte完全翻转，都无法带来执行路径的变化，那么这个byte很有可能是属于"data"，而非"metadata"（例如size, flag等），对整个fuzzing的意义不大。所以，在随后的一些变异中，会参考effector map，跳过那些“无效”的byte，从而节省了执行资源。

由此，通过极小的开销（没有增加额外的执行次数），AFL又一次对文件格式进行了启发式的判断。看到这里，不得不叹服于AFL实现上的精妙。

不过，在某些情况下并不会检测有效字符。第一种情况就是dumb mode或者从fuzzer，此时文件所有的字符都有可能被变异。第二、第三种情况与文件本身有关：

```c
/* Minimum input file length at which the effector logic kicks in: */

#define EFF_MIN_LEN         128

/* Maximum effector density past which everything is just fuzzed
   unconditionally (%): */

#define EFF_MAX_PERC        90
```

即默认情况下，如果文件小于128 bytes，那么所有字符都是“有效”的；同样地，如果AFL发现一个文件有超过90%的bytes都是“有效”的，那么也不差那10%了，大笔一挥，干脆把所有字符都划归为“有效”。

## arithmetic

在bitflip变异全部进行完成后，便进入下一个阶段：arithmetic。与bitflip类似的是，arithmetic根据目标大小的不同，也分为了多个子阶段：

- arith 8/8，每次对**8**个bit进行加减运算，按照每**8**个bit的步长从头开始，即对文件的每个byte进行整数加减变异
- arith 16/8，每次对**16**个bit进行加减运算，按照每**8**个bit的步长从头开始，即对文件的每个word进行整数加减变异
- arith 32/8，每次对**32**个bit进行加减运算，按照每**8**个bit的步长从头开始，即对文件的每个dword进行整数加减变异

加减变异的上限，在`config.h`中的宏`ARITH_MAX`定义，默认为35。所以，对目标整数会进行+1, +2, ..., +35, -1, -2, ..., -35的变异。特别地，由于整数存在大端序和小端序两种表示方式，AFL会贴心地对这两种整数表示方式都进行变异。

此外，AFL还会智能地跳过某些arithmetic变异。第一种情况就是前面提到的effector map：如果一个整数的所有bytes都被判断为“无效”，那么就跳过对整数的变异。第二种情况是之前bitflip已经生成过的变异：如果加/减某个数后，其效果与之前的某种bitflip相同，那么这次变异肯定在上一个阶段已经执行过了，此次便不会再执行。

## interest

下一个阶段是interest，具体可分为：

- interest 8/8，每次对**8**个bit进替换，按照每**8**个bit的步长从头开始，即对文件的每个byte进行替换
- interest 16/8，每次对**16**个bit进替换，按照每**8**个bit的步长从头开始，即对文件的每个word进行替换
- interest 32/8，每次对**32**个bit进替换，按照每**8**个bit的步长从头开始，即对文件的每个dword进行替换

而用于替换的"interesting values"，是AFL预设的一些比较特殊的数：

```c
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
```

这些数的定义在`config.h`文件中：

```c
/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */
```

可以看到，用于替换的基本都是可能会造成溢出的数。

与之前类似，effector map仍然会用于判断是否需要变异；此外，如果某个interesting value，是可以通过bitflip或者arithmetic变异达到，那么这样的重复性变异也是会跳过的。


## dictionary

进入到这个阶段，就接近deterministic fuzzing的尾声了。具体有以下子阶段：

- user extras (over)，从头开始，将**用户提供**的tokens依次**替换**到原文件中
- user extras (insert)，从头开始，将**用户提供**的tokens依次**插入**到原文件中
- auto extras (over)，从头开始，将**自动检测**的tokens依次**替换**到原文件中

其中，用户提供的tokens，是在词典文件中设置并通过`-x`选项指定的，如果没有则跳过相应的子阶段。

#### user extras (over)


对于用户提供的tokens，AFL先按照长度从小到大进行排序。这样做的好处是，只要按照顺序使用排序后的tokens，那么后面的token不会比之前的短，从而每次覆盖替换后不需要再恢复到原状。

随后，AFL会检查tokens的数量，如果数量大于预设的`MAX_DET_EXTRAS`（默认值为200），那么对每个token会根据概率来决定是否进行替换：

```c
    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }
```

这里的`UR(extras_cnt)`是运行时生成的一个`0`到`extras_cnt`之间的随机数。所以，如果用户词典中一共有400个tokens，那么每个token就有`200/400=50%`的概率执行替换变异。我们可以修改`MAX_DET_EXTRAS`的大小来调整这一概率。

由上述代码也可以看到，effector map在这里同样被使用了：如果要替换的目标bytes全部是“无效”的，那么就跳过这一段，对下一段目标执行替换。

#### user extras (insert)

这一子阶段是对用户提供的tokens执行插入变异。不过与上一个子阶段不同的是，此时并没有对tokens数量的限制，所以全部tokens都会从原文件的第1个byte开始，依次向后插入；此外，由于原文件并未发生替换，所以effector map不会被使用。

这一子阶段最特别的地方，就是变异不能简单地恢复。之前每次变异完，在变异位置处简单取逆即可，例如bitflip后，再进行一次同样的bitflip就恢复为原文件。正因为如此，之前的变异总体运算量并不大。

但是，对于**插入**这种变异方式，恢复起来则复杂的多，所以AFL采取的方式是：将原文件分割为插入前和插入后的部分，再加上插入的内容，将这3部分依次复制到目标缓冲区中（当然这里还有一些小的优化，具体可阅读代码）。而对每个token的每处插入，都需要进行上述过程。所以，如果用户提供了大量tokens，或者原文件很大，那么这一阶段的运算量就会非常的多。直观表现上，就是AFL的执行状态栏中，"user extras (insert)"的总执行量很大，执行时间很长。如果出现了这种情况，那么就可以考虑适当删减一些tokens。

#### auto extras (over)

这一项与"user extras (over)"很类似，区别在于，这里的tokens是最开始bitflip阶段自动生成的。另外，自动生成的tokens总量会由`USE_AUTO_EXTRAS`限制（默认为10）。

## havoc

对于非dumb mode的主fuzzer来说，完成了上述deterministic fuzzing后，便进入了充满随机性的这一阶段；对于dumb mode或者从fuzzer来说，则是直接从这一阶段开始。

havoc，顾名思义，是充满了各种随机生成的变异，是对原文件的“大破坏”。具体来说，havoc包含了对原文件的多轮变异，每一轮都是将多种方式组合（stacked）而成：

- 随机选取某个bit进行翻转
- 随机选取某个byte，将其设置为随机的interesting value
- 随机选取某个word，并随机选取大、小端序，将其设置为随机的interesting value
- 随机选取某个dword，并随机选取大、小端序，将其设置为随机的interesting value
- 随机选取某个byte，对其减去一个随机数
- 随机选取某个byte，对其加上一个随机数
- 随机选取某个word，并随机选取大、小端序，对其减去一个随机数
- 随机选取某个word，并随机选取大、小端序，对其加上一个随机数
- 随机选取某个dword，并随机选取大、小端序，对其减去一个随机数
- 随机选取某个dword，并随机选取大、小端序，对其加上一个随机数
- 随机选取某个byte，将其设置为随机数
- 随机删除一段bytes
- 随机选取一个位置，插入一段随机长度的内容，其中75%的概率是插入原文中随机位置的内容，25%的概率是插入一段随机选取的数
- 随机选取一个位置，替换为一段随机长度的内容，其中75%的概率是替换成原文中随机位置的内容，25%的概率是替换成一段随机选取的数
- 随机选取一个位置，用随机选取的token（用户提供的或自动生成的）替换
- 随机选取一个位置，用随机选取的token（用户提供的或自动生成的）插入

怎么样，看完上面这么多的“随机”，有没有觉得晕？还没完，AFL会生成一个随机数，作为变异组合的数量，并根据这个数量，每次从上面那些方式中随机选取一个（可以参考高中数学的有放回摸球），依次作用到文件上。如此这般丧心病狂的变异，原文件就大概率面目全非了，而这么多的随机性，也就成了fuzzing过程中的不可控因素，即所谓的“看天吃饭”了。

## splice

历经了如此多的考验，文件的变异也进入到了最后的阶段：splice。如其意思所说，splice是将两个seed文件拼接得到新的文件，并对这个新文件继续执行havoc变异。

具体地，AFL在seed文件队列中随机选取一个，与当前的seed文件做对比。如果两者差别不大，就再重新随机选一个；如果两者相差比较明显，那么就随机选取一个位置，将两者都分割为头部和尾部。最后，将当前文件的头部与随机文件的尾部拼接起来，就得到了新的文件。在这里，AFL还会过滤掉拼接文件未发生变化的情况。

## cycle

于是乎，一个seed文件，在上述的全部变异都执行完成后，就...抱歉，还没结束。

上面的变异完成后，AFL会对文件队列的下一个进行变异处理。当队列中的全部文件都变异测试后，就完成了一个"cycle"，这个就是AFL状态栏右上角的"cycles done"。而正如cycle的意思所说，整个队列又会从第一个文件开始，再次进行变异，不过与第一次变异不同的是，这一次就不需要再进行deterministic fuzzing了。

当然，如果用户不停止AFL，那么seed文件将会一遍遍的变异下去。

## 总结

从以上介绍内容来看，AFL的文件变异，既有看天吃饭的成分，也有随着fuzzing启发式的判断，结合了这么多种方式和巧妙的思路，不愧是大名鼎鼎的AFL。
