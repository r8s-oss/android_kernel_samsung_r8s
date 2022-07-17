// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

#include <kunit/test.h>

#include "../migration/mcps_migration.h"

extern int __mcps_run_migration(struct migration_manager *manager);
extern struct migration_request *__mcps_dequeue_migration_request(struct migration_manager *manager);
extern struct migration_request *mcps_dequeue_migration_request(void);
extern int __mcps_push_migration_request(struct migration_manager *manager, struct migration_request *req);
extern struct migration_request *mcps_make_migration_request(unsigned int from, unsigned int to, unsigned int option);
extern int mcps_migration_request_cb(const char *buf, const struct kernel_param *kp);
extern int __init_migration_manager(struct migration_manager *manager, void (*handler)(unsigned int, unsigned int, unsigned int));
extern void __release_migration_manager(struct migration_manager *manager);
extern void init_migration_manager(void (*handler)(unsigned int, unsigned int, unsigned int));
extern void release_migration_manager(void);

struct input_migration_expectation {
	const char *input;
	unsigned int expected_from;
	unsigned int expected_to;
	unsigned int expected_option;
};

#define SIZE_TEST_SUCCESS_MIGRATION_REQUEST 6
static struct input_migration_expectation test_success_migration_request[] = {
	{
		.input = "0 1 0",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 0,
	},

	{
		.input = "0 1 1",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 1,
	},

	{
		.input = "7 0 0",
		.expected_from = 7,
		.expected_to = 0,
		.expected_option = 0,
	},

	{
		.input = "4294967295 1 2",
		.expected_from = 4294967295,
		.expected_to = 1,
		.expected_option = 2,
	},

	{
		.input = "123 1 2",
		.expected_from = 123,
		.expected_to = 1,
		.expected_option = 2,
	},

	{
		.input = "1 1 2",
		.expected_from = 1,
		.expected_to = 1,
		.expected_option = 2,
	},
};

#define SIZE_TEST_FAIL_MIGRATION_REQUEST 15
static struct input_migration_expectation test_fail_migration_request[] = {
	{
		.input = "999 1 0",
		.expected_from = 999,
		.expected_to = 1,
		.expected_option = 0,
	},

	{
		.input = "9 1 0",
		.expected_from = 9,
		.expected_to = 1,
		.expected_option = 0,
	},

	{
		.input = "0 1 9",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 9,
	},

	{
		.input = "0 1 999",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 999,
	},

	{
		.input = "1 1 999",
		.expected_from = 1,
		.expected_to = 1,
		.expected_option = 999,
	},

	{
		.input = "111111",
		.expected_from = 111111,
		.expected_to = 999999,
		.expected_option = 999999,
	},

	{
		.input = "1",
		.expected_from = 1,
		.expected_to = 999999,
		.expected_option = 999999,
	},

	{
		.input = "0 1",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 999999,
	},

	{
		.input = "0  1",
		.expected_from = 0,
		.expected_to = 999999,
		.expected_option = 1,
	},

	{
		.input = "0 1 ",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 999999,
	},

	{
		.input = "0 1  1",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 999999,
	},

	{
		.input = "0 a 1",
		.expected_from = 0,
		.expected_to = (unsigned int)'a',
		.expected_option = 999999,
	},

	{
		.input = "0 1 c",
		.expected_from = 0,
		.expected_to = 1,
		.expected_option = 999999,
	},

	{
		.input = "4294967295 1 0",
		.expected_from = 4294967295,
		.expected_to = 1,
		.expected_option = 0,
	},

	{
		.input = "1 1 0",
		.expected_from = 1,
		.expected_to = 1,
		.expected_option = 0,
	},
};

void mcps_migration_kunit_handler(unsigned int from, unsigned int to, unsigned int option) {}

static void test_init_migration_manager_when_no_handler_then_return_errorcode(struct test *test)
{
	//Arrange
	struct migration_manager *manager = test_kzalloc(test, sizeof(struct migration_manager), GFP_KERNEL);
	int ret = 0;

	//Act
	ret = __init_migration_manager(manager, NULL);

	//Assert
	EXPECT_EQ(test, ret, -EINVAL);
}

static void test_init_migration_manager_with_handler_then_return_zero(struct test *test)
{
	//Arrange
	struct migration_manager *manager = test_kzalloc(test, sizeof(struct migration_manager), GFP_KERNEL);
	int ret = 0;

	//Act
	ret = __init_migration_manager(manager, mcps_migration_kunit_handler);

	//Assert
	EXPECT_EQ(test, ret, 0);
}

static void test_mcps_push_migration_request_when_too_much_enqueue_then_reject_to_push(struct test *test)
{
	//Arrange
	int ret = 0;
	int count = 0;
	struct migration_request *req;
	struct migration_manager *manager = (struct migration_manager *)test->priv;

	//Act
	for (count = 0; count < MAX_MIGRATION_REQUEST; count++) {
		req = mcps_make_migration_request(0, 1, 0);
		ret = __mcps_push_migration_request(manager, req);

		//Assert
		EXPECT_EQ(test, ret, 0);
	}

	//Act
	for (count = 0; count < MAX_MIGRATION_REQUEST; count++) {
		req = mcps_make_migration_request(0, 1, 0);
		ret = __mcps_push_migration_request(manager, req);

		//Assert
		EXPECT_EQ(test, ret, -EINVAL);
	}

	//Act
	count = __mcps_run_migration(manager);
	EXPECT_EQ(test, count, MAX_MIGRATION_REQUEST);

	//Act
	for (count = 0; count < MAX_MIGRATION_REQUEST; count++) {
		req = mcps_make_migration_request(0, 1, 0);
		ret = __mcps_push_migration_request(manager, req);

		//Assert
		EXPECT_EQ(test, ret, 0);
	}
}

static void test_mcps_make_migration_request_when_successful_input_then_success_to_enqueue(struct test *test)
{
	int i = 0;

	for (i = 0; i < SIZE_TEST_SUCCESS_MIGRATION_REQUEST; i++) {
		//Arrange
		struct input_migration_expectation *test_param = &test_success_migration_request[i];
		struct migration_request *req, *dequeued;
		struct migration_manager *manager = (struct migration_manager *)test->priv;

		//Act
		req = mcps_make_migration_request(test_param->expected_from,
										test_param->expected_to,
										test_param->expected_option);

		//Assert
		ASSERT_NOT_ERR_OR_NULL(test, req);
		EXPECT_EQ(test, req->from, test_param->expected_from);
		EXPECT_EQ(test, req->to, test_param->expected_to);
		EXPECT_EQ(test, req->option, test_param->expected_option);

		//Act
		__mcps_push_migration_request(manager, req);
		dequeued = __mcps_dequeue_migration_request(manager);

		//Assert
		ASSERT_NOT_ERR_OR_NULL(test, dequeued);
		EXPECT_EQ(test, req->from, dequeued->from);
		EXPECT_EQ(test, req->to, dequeued->to);
		EXPECT_EQ(test, req->option, dequeued->option);

		kfree(req);

		if (req != dequeued)
			kfree(dequeued);
	}

}

static void test_mcps_make_migration_request_when_failure_input_then_return_null(struct test *test)
{
	int i = 0 ;

	for (i = 0; i < SIZE_TEST_FAIL_MIGRATION_REQUEST; i++) {
		//Arrange
		struct input_migration_expectation *test_param = &test_fail_migration_request[i];

		//Act
		struct migration_request *req = mcps_make_migration_request(test_param->expected_from,
																	test_param->expected_to,
																	test_param->expected_option);

		//Assert
		EXPECT_EQ(test, req, NULL);

		kfree(req);
	}
}

static void test_mcps_migration_request_cb_when_successful_input_then_success_to_enqueue(struct test *test)
{
	int i = 0 ;

	for (i = 0; i < SIZE_TEST_SUCCESS_MIGRATION_REQUEST; i++) {
		//Arrange
		struct input_migration_expectation *test_param = &test_success_migration_request[i];
		int len = 0;
		struct migration_request *dequeued;

		init_migration_manager(NULL);

		//Act
		len = mcps_migration_request_cb(test_param->input, NULL);
		dequeued = mcps_dequeue_migration_request();

		//Assert
		EXPECT_EQ(test, len, strlen(test_param->input));
		ASSERT_NOT_ERR_OR_NULL(test, dequeued);
		EXPECT_EQ(test, dequeued->from, test_param->expected_from);
		EXPECT_EQ(test, dequeued->to, test_param->expected_to);
		EXPECT_EQ(test, dequeued->option, test_param->expected_option);

		kfree(dequeued);

		release_migration_manager();
	}
}

static void test_mcps_migration_request_cb_when_failure_input_then_fail_to_enqueue(struct test *test)
{
		int i = 0 ;

	for (i = 0; i < SIZE_TEST_FAIL_MIGRATION_REQUEST; i++) {
		//Arrange
		struct input_migration_expectation *test_param = &test_fail_migration_request[i];
		int len = 0;
		struct migration_request *dequeued;

		init_migration_manager(NULL);

		//Act
		len = mcps_migration_request_cb(test_param->input, NULL);
		dequeued = mcps_dequeue_migration_request();

		//Assert
		EXPECT_EQ(test, len, 0);
		EXPECT_EQ(test, dequeued, NULL);

		release_migration_manager();
	}
}

#if !defined(CONFIG_UML)
#endif

int mcps_migration_test_init(struct test *test)
{
	struct migration_manager *manager = test_kzalloc(test, sizeof(struct migration_manager), GFP_KERNEL);

	__init_migration_manager(manager, mcps_migration_kunit_handler);

	test->priv = manager;

	return 0;
}

void mcps_migration_test_exit(struct test *test)
{
	__release_migration_manager(test->priv);
}

static struct test_case mcps_migration_test_cases[] = {
#if !defined(CONFIG_UML)
#endif
	TEST_CASE(test_init_migration_manager_when_no_handler_then_return_errorcode),
	TEST_CASE(test_init_migration_manager_with_handler_then_return_zero),
	TEST_CASE(test_mcps_push_migration_request_when_too_much_enqueue_then_reject_to_push),
	TEST_CASE(test_mcps_make_migration_request_when_successful_input_then_success_to_enqueue),
	TEST_CASE(test_mcps_make_migration_request_when_failure_input_then_return_null),
	TEST_CASE(test_mcps_migration_request_cb_when_successful_input_then_success_to_enqueue),
	TEST_CASE(test_mcps_migration_request_cb_when_failure_input_then_fail_to_enqueue),
	{}
};

static struct test_module mcps_migration_test_suite = {
	.name = "mcps-migration_test",
	.init = mcps_migration_test_init,
	.exit = mcps_migration_test_exit,
	.test_cases = mcps_migration_test_cases,
};
module_test(mcps_migration_test_suite);
