#!/bin/python3
""" script that generate trace group info """
import subprocess
import sys
import yaml


def parse_group(group):
    """ parse group in yaml file """
    if 'children' not in group:
        return
    children = group['children']
    i = 0
    while i < len(children):
        child = children[i]
        if not isinstance(child, str):
            parse_group(child)
            i += 1
            names = child['name'].split(':')
            if len(names) > 1:
                child['name'] = names[0]
                child['skb'] = names[1]
            continue
        children.remove(child)
        data = child.split(':')
        if len(data) <= 1:
            child = {
                "name": data[0]
            }
        else:
            child = {
                "name": data[0],
                "skb": int(data[1])
            }
        children.insert(i, child)
        i += 1


def gen_group_init(group, name):
    return '''trace_group_t {name} = {{
	.name = "{}",
	.desc = "{}",
	.children = LIST_HEAD_INIT({name}.children),
	.traces = LIST_HEAD_INIT({name}.traces),
	.list = LIST_HEAD_INIT({name}.list),
}};
'''.format(group['name'], group.get('desc'), name=name,)


global_status = {}
global_names = {}
global_status['trace_index'] = 0

rule_levels = {
    'info': 'RULE_INFO',
    'warn': 'RULE_WARN',
    'error': 'RULE_ERROR',
}
rule_types = {
    'eq': 'RULE_RETURN_EQ',
    'lt': 'RULE_RETURN_LT',
    'gt': 'RULE_RETURN_GT',
    'ne': 'RULE_RETURN_NE',
    'range': 'RULE_RETURN_RANGE',
    'any': 'RULE_RETURN_ANY',
}


def gen_name(name, is_trace=False):
    if is_trace:
        name = name.replace('-', '_')
    else:
        name = ('__group_' + name).replace('-', '_')
    if name in global_names:
        global_names[name] += 1
        return '{}_{}'.format(name, global_names[name])
    global_names[name] = 0
    return name


def gen_group(group, is_root=False):
    if 'children' not in group:
        return

    define_str = ''
    init_str = ''
    probe_str = ''
    index_str = ''

    if is_root:
        p_name = 'root_group'
        group['define_name'] = p_name
        define_str += gen_group_init(group, p_name)
    else:
        p_name = group['define_name']

    for child in group['children']:
        if 'children' in child:
            name = gen_name(child["name"])
            child['define_name'] = name
            define_str += gen_group_init(child, name)
            init_str += '\tlist_add_tail(&{}.list, &{}.children);\n'.format(name, p_name)
            (_define_str, _init_str, _probe_str, _index_str) = gen_group(child)
            define_str += _define_str
            init_str += _init_str
            probe_str += _probe_str
            index_str += _index_str
        else:
            name = gen_name(child["name"], True)
            child['define_name'] = name
            skb_str = ''
            index_str += '#define INDEX_{} {}\n'.format(
                name, global_status["trace_index"])
            if 'tp' in child:
                trace_type = 'TRACE_TP'
                tp = child['tp'].split(':')
                skb_str = '\n\t.tp = "{}",'.format(child["tp"])
                if 'skb' in child:
                    probe_str += '\tFN_tp({}, {}, {}, 8)\t\\\n'.format(name,
                                                                       tp[0], tp[1])
            else:
                trace_type = 'TRACE_FUNCTION'
                if 'skb' in child:
                    skb_str = '\n\t.skb = {},'.format(child["skb"])
                    probe_str += '\tFN({}, {})\t\\\n'.format(name,
                                                             int(child["skb"]) + 1)
            if 'analyzer' in child:
                analyzer = '\n\t.analyzer = &ANALYZER({}),'.format(
                    child["analyzer"])
            else:
                analyzer = ''
            rule_str = ''
            if 'rules' in child:
                rules = child['rules']
                for index, rule in enumerate(rules):
                    level = rule['level']
                    rule_tmp = '\t.level = {},\n'.format(rule_levels[level])
                    exps = rule['exp'].split(' ')
                    rule_type = rule_types[exps[0]]
                    if exps[0] == 'range':
                        ranges = exps[1].split('-')
                        rule_tmp += '\t.range = {{ .min = {}, .max = {}}},\n'.format(
                            ranges[0], ranges[1])
                    elif exps[0] != 'any':
                        rule_tmp += '\t.expected = {},\n'.format(exps[1])
                    rule_tmp += '\t.type = {},\n'.format(rule_type)
                    if 'adv' in rule:
                        rule_adv = rule["adv"].replace('\n', '\\n')
                        rule_tmp += '\t.adv = "{}",\n'.format(rule_adv)
                    msg = 'PFMT_EMPH"{}"PFMT_END'.format(rule["msg"])
                    if level == 'warn':
                        msg = 'PFMT_WARN"{}"PFMT_END'.format(rule["msg"])
                    elif level == 'error':
                        msg = 'PFMT_ERROR"{}"PFMT_END'.format(rule["msg"])
                    rule_tmp += '\t.msg = {},\n'.format(msg)
                    rule_name = 'rule_{}_{}'.format(name, index)
                    rule_str += 'rule_t {} = {{{}}};\n'.format(
                        rule_name, rule_tmp)
                    init_str += '\tlist_add_tail(&{}.list, &{}.rules);\n'.format(
                        rule_name, name)

            if_str = '\n\t.if_str = "{}",'.format(
                child.get("if")) if 'if' in child else ''
            reg_str = '\n\t.regex = "",'.format(
                {child["regex"]}) if 'regex' in child else ''
            msg_str = '\n\t.msg = "{}",'.format(
                child["msg"]) if 'msg' in child else ''
            default = True
            if 'default' in child:
                default = child['default']
            elif 'default' in group:
                default = group['default']
            default = 'true' if default else 'false'
            default = '\n\t.def = {},'.format(default)
            target = child.get('target') or child['name']
            define_str += '''trace_t {name} = {{
\t.name = "{}",
\t.desc = "{}",{}{}{}
\t.type = {},{}{}{}
\t.index = INDEX_{name},
\t.prog = "__trace_{name}",
\t.parent = &{},
\t.rules =  LIST_HEAD_INIT({name}.rules),
}};
{}
'''.format(target, child.get('desc'), skb_str, if_str, default, trace_type,
                reg_str, analyzer, msg_str, p_name, rule_str,name=name)
            init_str += '''\tlist_add_tail(&{name}.list, &{}.traces);
\tall_traces[INDEX_{name}] = &{name};
\tlist_add_tail(&{name}.sibling, &trace_list);
'''.format(p_name, name=name)
            global_status['trace_index'] += 1

    return (define_str, init_str, probe_str, index_str)


with open('trace.yaml', 'r', encoding='utf-8') as f:
    content = f.read()
    root = yaml.load(content, yaml.SafeLoader)
    parse_group(root)
    (all_define_str, all_init_str, all_probe_str,
     all_index_str) = gen_group(root, root)

    if len(sys.argv) > 1 and sys.argv[1] == 'probe':
        print('''{}
#define TRACE_MAX {}
#define _DEFINE_PROBE(FN, FN_tp)\t\t\\
{}
'''.format(all_index_str,global_status['trace_index'],all_probe_str))
    else:
        print('''#include "trace.h"
#include "progs/kprobe_trace.h"
#include "analysis.h"

{}

trace_t *all_traces[TRACE_MAX];
int trace_count = TRACE_MAX;
LIST_HEAD(trace_list);

void init_trace_group()
{{
{}
}}
'''.format(all_define_str,all_init_str))
