<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Create users table migration for testing.
 *
 * Creates a minimal users table with the essential columns needed for
 * testing the Bearer package functionality. This table is used by
 * the User fixture model in tests.
 *
 * The table includes:
 * - id: Auto-incrementing primary key
 * - name: User's display name
 * - email: Unique email address for authentication
 * - password: Hashed password
 * - Timestamps for created_at and updated_at
 *
 * @author Brian Faust <brian@cline.sh>
 */
return new class() extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
