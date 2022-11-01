// Copyright © 2022 Alexandre Detiste <alexandre@detiste.be>
// SPDX-License-Identifier: GPL-2.0-or-later

#include <iostream>
#include <map>
#include <algorithm>
#include <ctime>
#include <cstring>

#include <getopt.h>

#include "explain.h"
#include "filters.h"
#include "locate.h"
#include "dpkg.h"
#include "shellexp.h"

using namespace std;

#ifndef BUSTER
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
using namespace std::experimental;
namespace fs = std::experimental::filesystem;
#endif

static clock_t beg = clock();

static void elapsed(const string& action)
{
	if (getenv("ELAPSED") == nullptr) return;
	clock_t end = clock();
	clock_t elapsed_mseconds = (end - beg) * 1000 / CLOCKS_PER_SEC;
	cerr << "elapsed " << action << ": " << elapsed_mseconds << endl;
	beg = end;
}

static void output_pigs(long unsigned int limit, const map<string, size_t>& usage)
{
	vector<pair<string,size_t>> pigs;
	copy(usage.begin(), usage.end(), back_inserter(pigs));
	sort(pigs.rbegin(), pigs.rend(), [](const auto &left,
					    const auto &right) {
		return left.second < right.second;
	});
	for (size_t i = 0; i < pigs.size() && i < limit; ++i) {
		if (pigs[i].second > 0) cout << pigs[i].second << " " << pigs[i].first << endl;
	}
}

static void output_ncdu(const vector<string>& cruft_db)
{
	// https://dev.yorhel.nl/ncdu/jsonfmt
	// https://github.com/rofl0r/ncdu/blob/master/src/dir_export.c

	cout << "[1,0,{\"progname\": \"cpigs\", \"progver\": \"0.9\",";
	cout << "\"timestamp\": " <<  int(time(nullptr)) << "},\n";

	cout << "[{\"name\":\"/\"}"; // not the ','

	fs::path last_dir = "/";

	for (const auto& cr: cruft_db)
	{
		fs::path cruft = cr;
		fs::path dirname;
		error_code ec;

		if (fs::is_directory(cruft, ec)) {
			dirname = cruft;
		} else {
			dirname = cruft.parent_path();
		}

		if (last_dir != dirname)
		{
			auto l = last_dir.begin();
			auto d = dirname.begin();
			int common_len = 0;
			while(l != last_dir.end() && d != dirname.end() && *l == *d)
			{
				common_len++;
				l++;
				d++;
			}

			int len_last_dir = 0;
			for(l = last_dir.begin(); l != last_dir.end() ;l++) len_last_dir++;

			int closed = len_last_dir - common_len;
			for(int c = closed; c; c--) cout << ']';

			int skipped = 0;
			for(auto& part : dirname)
			{
				if (skipped >= common_len) {
				        cout << ",\n[{\"name\":" << part << "}";
				}
				skipped++;
			}
			last_dir = dirname;
		}

		if (!fs::is_directory(cruft, ec)) {
			fs::path basename = cruft.filename();
			cout << ",\n{\"name\":" << basename;
			try {
				if(fs::is_symlink(cruft)) {
					// some arbitrary value
					// still better than  /var/cache/pbuilder/base.cow/dev/core -> /proc/kcore
					// showing up as 128 TiB and dwarfing everything else
					cout << ",\"dsize\":1024";
				} else {
					auto fsize = fs::file_size(cruft);
					cout << ",\"dsize\":" << fsize;
				}
			}
			catch (...) {}
			cout << "}";
		}
	}

	for(auto& part : last_dir) { cout << ']'; }
	cout << "]" << endl;
}

static const char* const default_explain_dir = "/etc/cruft/explain/";
static const char* const default_filter_dir = "/etc/cruft/filters/";
static const char* const default_ruleset_file = "/usr/share/cruft/ruleset";

static int usage()
{
	cerr << "usage:\n";
	cerr << "  cpigs [-n] [NUMBER]  : default format\n";
	cerr << "  cpigs -e             : export in ncdu format\n";
	cerr << "  cpigs -c             : export in .csv format\n";
	cerr << "  cpigs -C             : export in .csv format, also static files\n";

	cerr << "  cpigs -E --explain     directory for explain scripts (default: " << default_explain_dir << ")\n";
	cerr << "  cpigs -F --filter      directory for filters (default: " << default_filter_dir << ")\n";
	cerr << "  cpigs -R --ruleset     path for ruleset file (default: " << default_ruleset_file << ")\n";
	return 1;
}

int main(int argc, char *argv[])
{
	bool ncdu = false, csv = false, static_ = false;
	long unsigned int limit = 10;
	string explain_dir = default_explain_dir;
	string filter_dir = default_filter_dir;
	string ruleset_file = default_ruleset_file;

	const struct option long_options[] =
	{
		{"csv", no_argument, nullptr, 'c'},
		{"csv_static", no_argument, nullptr, 'C'},
		{"ncdu", no_argument, nullptr, 'e'},
		{"explain", required_argument, nullptr, 'E'},
		{"filter", required_argument, nullptr, 'F'},
		{"help", no_argument, nullptr, 'h'},
		{"limit", required_argument, nullptr, 'l'},
		{"normal", no_argument, nullptr, 'n'},
		{"ruleset", required_argument, nullptr, 'R'},
	};

	int opt, opti = 0;
	while ((opt = getopt_long(argc, argv, "cCeE:F:hlnR:", long_options, &opti)) != 0) {
		if (opt == EOF)
			break;

		switch (opt) {

		case 'c':
			csv = true;
			break;

		case 'C':
			csv = true;
			static_ = true;
			break;

		case 'e':
			ncdu = true;
			break;

		case 'E':
			explain_dir = optarg;
			if (!explain_dir.empty() && explain_dir.back() != '/')
				explain_dir += '/';
			break;

		case 'F':
			filter_dir = optarg;
			if (!filter_dir.empty() && filter_dir.back() != '/')
				filter_dir += '/';
			break;

		case 'h':
			usage();
			exit(0);

		case 'l':
			try {
				limit = stoul(optarg);
			} catch(...) { 
				usage();
				exit(1);
			}
			break;

		case 'n':
			csv = false;
			static_ = false;
			break;

		case 'R':
			ruleset_file = optarg;
			break;

		case '?':
			break;

		default:
			cerr << "Invalid getopt return value: " << opt << "\n";
			break;
		}
	}

	if (optind < argc) {
		cerr << "Invalid non-option arguments:";
		while (optind < argc)
			cerr << " " << argv[optind++];
		cerr << '\n';
		usage();
		exit(1);
	}

	vector<string> fs;
	read_locate(fs, "/usr/share/cruft/ignore");
	elapsed("plocate");

	if (csv) cout << "path;package;type;cruft;size" << endl;

	vector<string> packages;
	vector<string> dpkg;
	read_dpkg(packages, dpkg, static_);
	elapsed("dpkg");

	vector<string> cruft_db;
	for (auto left = fs.begin(), right = dpkg.begin(); left != fs.end(); )
	{
		if (*left==*right) {
			left++;
			right++;
		} else if (*left < *right) {
			cruft_db.push_back(*left);
			left++;
		} else {
			right++;
		}
		if (right == dpkg.end())
			while(left !=fs.end()) {cruft_db.push_back(*left); left++;}
	}
	elapsed("main set match");

	if (ncdu) {
		output_ncdu(cruft_db);
		return 0;
	}

	vector<owner> globs;
	read_filters(filter_dir, ruleset_file, packages,globs);
	read_explain(explain_dir, packages,globs);
	elapsed("read filters");

	std::map<std::string, size_t> usage{{"UNKNOWN", 0}};

	for (const auto& cruft: cruft_db) {
		string package = "UNKNOWN";
		for (const auto& owners: globs) {
			bool match;
			match = myglob(cruft,owners.glob);
			if (match) {
				package = owners.package;
				break;
			}
		}

		char type;
		size_t fsize;
		try
		{
			if (fs::is_symlink(cruft)) {
				type = 'l';
				fsize = 1024;
			} else if (fs::is_directory(cruft)) {
				type = 'd';
				fsize = 1024;
			} else {
				type = 'f';
				fsize = fs::file_size(cruft);
			}
		}
		catch (...) {
			type = '?';
			fsize = 1024;
		}

		if (csv) {
			cout << cruft << ';' << package << ';' << type << ";1;" << fsize << endl;
		} else {
			if (usage.count(package) == 0) usage[package] = 0;
			usage[package] += fsize;
		}
	}
	elapsed("extra vs globs");

	output_pigs(limit, usage);

	return 0;
}
